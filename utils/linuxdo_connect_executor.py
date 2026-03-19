#!/usr/bin/env python3
"""
Linux.do Connect 长生命周期浏览器执行器
"""

import asyncio
import hashlib
import json
import os
import time
from copy import deepcopy

from camoufox.async_api import AsyncCamoufox

BLOCKED_RESOURCE_TYPES = {
	'stylesheet',
	'image',
	'font',
	'media',
	'texttrack',
	'manifest',
	'ping',
	'cspviolationreport',
	'prefetch',
	'websocket',
	'eventsource',
}
BLOCKED_URL_KEYWORDS = (
	'static.cloudflareinsights.com',
	'google-analytics.com',
	'googletagmanager.com',
	'doubleclick.net',
	'clarity.ms',
	'umami',
	'plausible',
	'beacon.min.js',
)
LINUXDO_CONNECT_EXECUTOR_IDLE_TTL_SECONDS = max(
	0,
	int(os.getenv('LINUXDO_CONNECT_EXECUTOR_IDLE_TTL_SECONDS', '180')),
)
DEFAULT_LINUXDO_CONNECT_METRICS_FILE = 'storage-states/linuxdo-connect-metrics.json'


def linuxdo_connect_executor_enabled() -> bool:
	"""是否启用 Linux.do Connect 长生命周期执行器"""
	raw_value = os.getenv('ENABLE_LINUXDO_CONNECT_EXECUTOR', 'true')
	return raw_value.strip().lower() in {'1', 'true', 'yes', 'on'}


def linuxdo_signin_check_html_enabled() -> bool:
	"""是否保存授权页调试 HTML"""
	raw_value = os.getenv('LINUXDO_SAVE_SIGNIN_CHECK_HTML', '')
	return raw_value.strip().lower() in {'1', 'true', 'yes', 'on'}


def linuxdo_connect_metrics_enabled() -> bool:
	"""是否启用 LinuxDo Connect 指标收集"""
	raw_value = os.getenv('ENABLE_LINUXDO_CONNECT_METRICS', 'true')
	return raw_value.strip().lower() in {'1', 'true', 'yes', 'on'}


def get_linuxdo_connect_metrics_file() -> str:
	"""返回 LinuxDo Connect 指标文件路径"""
	return os.getenv('LINUXDO_CONNECT_METRICS_FILE', DEFAULT_LINUXDO_CONNECT_METRICS_FILE)


def _build_storage_state_identity(storage_state) -> str:
	"""为 storage state 构造稳定标识，用于判断是否需要重建上下文"""
	if isinstance(storage_state, str):
		try:
			stat = os.stat(storage_state)
			return f'path:{storage_state}:{int(stat.st_mtime)}:{stat.st_size}'
		except FileNotFoundError:
			return f'path:{storage_state}:missing'

	try:
		payload = json.dumps(storage_state, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
	except Exception:
		payload = repr(storage_state)
	return f'inline:{hashlib.sha256(payload.encode("utf-8")).hexdigest()}'


class LinuxDoConnectExecutor:
	"""单个 Linux.do 账号的 connect 执行器"""

	def __init__(self, username: str):
		self.username = username
		self.username_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()[:8]
		self._camoufox = None
		self._browser = None
		self._context = None
		self._page = None
		self._storage_state_identity = ''
		self._lock = asyncio.Lock()
		self._last_used_monotonic = 0.0

	def touch(self):
		"""刷新最近使用时间"""
		self._last_used_monotonic = time.monotonic()

	def is_idle_expired(self, now_monotonic: float) -> bool:
		"""判断执行器是否已空闲超时"""
		if LINUXDO_CONNECT_EXECUTOR_IDLE_TTL_SECONDS <= 0:
			return False
		if self._lock.locked():
			return False
		if self._context is None:
			return False
		return (now_monotonic - self._last_used_monotonic) >= LINUXDO_CONNECT_EXECUTOR_IDLE_TTL_SECONDS

	async def _resource_handler(self, route, request):
		resource_type = (request.resource_type or '').lower()
		url = request.url.lower()
		if resource_type in BLOCKED_RESOURCE_TYPES or any(keyword in url for keyword in BLOCKED_URL_KEYWORDS):
			await route.abort()
			return
		await route.continue_()

	async def ensure_context(self, storage_state):
		"""确保长生命周期 context 已初始化"""
		expected_identity = _build_storage_state_identity(storage_state)
		if self._context is not None and self._storage_state_identity == expected_identity:
			self.touch()
			return self._context

		await self.close()
		self._camoufox = AsyncCamoufox(
			headless=True,
			humanize=True,
			locale='en-US',
		)
		self._browser = await self._camoufox.__aenter__()
		self._context = await self._browser.new_context(storage_state=storage_state)
		await self._context.route('**/*', self._resource_handler)
		self._storage_state_identity = expected_identity
		self.touch()
		LinuxDoConnectExecutorManager.record_metric('executor_created')
		print(f'ℹ️ LinuxDoConnectExecutor [{self.username_hash}]: context ready')
		return self._context

	async def acquire_page(self, storage_state, extra_cookies: list | None = None):
		"""基于长生命周期 context 获取可复用页面"""
		context = await self.ensure_context(storage_state)
		if extra_cookies:
			await context.add_cookies(extra_cookies)
		page_reused = False
		try:
			page_reused = self._page is not None and not self._page.is_closed()
		except Exception:
			page_reused = False

		if not page_reused:
			self._page = await context.new_page()
			LinuxDoConnectExecutorManager.record_metric('page_created')
		else:
			LinuxDoConnectExecutorManager.record_metric('page_reused')
			try:
				await self._page.goto('about:blank', wait_until='commit', timeout=5000)
			except Exception:
				pass

		self.touch()
		return self._page

	async def release_page(self):
		"""释放页面使用权，仅刷新空闲时间"""
		self.touch()

	async def close(self):
		"""关闭执行器"""
		if self._page is not None:
			try:
				await self._page.close()
			except Exception:
				pass
			self._page = None
		if self._context is not None:
			try:
				await self._context.close()
			except Exception:
				pass
			self._context = None
		if self._camoufox is not None:
			try:
				await self._camoufox.__aexit__(None, None, None)
			except Exception:
				pass
			self._camoufox = None
			self._browser = None
		self._storage_state_identity = ''
		self._last_used_monotonic = 0.0


class LinuxDoConnectExecutorManager:
	"""Linux.do Connect 执行器管理器"""

	_executors: dict[str, LinuxDoConnectExecutor] = {}
	_manager_lock = asyncio.Lock()
	_metrics = {
		'executor_created': 0,
		'executor_reused': 0,
		'executor_closed_idle': 0,
		'page_created': 0,
		'page_reused': 0,
		'fast_path_attempts': 0,
		'fast_path_success': 0,
		'fast_path_fallback': 0,
		'approve_direct_jump': 0,
		'callback_capture_hits': 0,
		'authorize_total_ms': 0.0,
		'challenge_wait_ms': 0.0,
		'callback_capture_ms': 0.0,
	}

	@classmethod
	def record_metric(cls, name: str, increment: int = 1, duration_ms: float | None = None):
		"""记录内存指标"""
		if not linuxdo_connect_metrics_enabled():
			return
		cls._metrics[name] = cls._metrics.get(name, 0) + increment
		if duration_ms is not None:
			duration_key = f'{name}_total_ms'
			cls._metrics[duration_key] = cls._metrics.get(duration_key, 0.0) + duration_ms

	@classmethod
	def record_duration(cls, name: str, duration_ms: float):
		"""记录耗时指标"""
		if not linuxdo_connect_metrics_enabled():
			return
		cls._metrics[name] = cls._metrics.get(name, 0.0) + duration_ms

	@classmethod
	def get_metrics_snapshot(cls) -> dict:
		"""获取指标快照"""
		metrics = deepcopy(cls._metrics)
		attempts = int(metrics.get('fast_path_attempts', 0))
		callback_hits = int(metrics.get('callback_capture_hits', 0))
		metrics['active_executor_count'] = len(cls._executors)
		metrics['fast_path_avg_ms'] = round(metrics.get('authorize_total_ms', 0.0) / attempts, 2) if attempts else 0.0
		metrics['callback_capture_avg_ms'] = (
			round(metrics.get('callback_capture_ms', 0.0) / callback_hits, 2)
			if callback_hits else 0.0
		)
		return metrics

	@classmethod
	def save_metrics_snapshot(cls, metrics_file: str | None = None):
		"""保存指标快照"""
		if not linuxdo_connect_metrics_enabled():
			return
		target_file = metrics_file or get_linuxdo_connect_metrics_file()
		if not target_file:
			return
		try:
			target_dir = os.path.dirname(target_file)
			if target_dir:
				os.makedirs(target_dir, exist_ok=True)
			with open(target_file, 'w', encoding='utf-8') as f:
				json.dump(cls.get_metrics_snapshot(), f, ensure_ascii=False, indent=2)
		except Exception as e:
			print(f'⚠️ LinuxDoConnectExecutorManager: failed to save metrics snapshot: {e}')

	@classmethod
	async def sweep_idle_executors(cls):
		"""关闭空闲超时的执行器"""
		now_monotonic = time.monotonic()
		async with cls._manager_lock:
			stale_items = [
				(username_hash, executor)
				for username_hash, executor in cls._executors.items()
				if executor.is_idle_expired(now_monotonic)
			]
			for username_hash, _ in stale_items:
				cls._executors.pop(username_hash, None)
		for username_hash, executor in stale_items:
			print(f'ℹ️ LinuxDoConnectExecutorManager: closing idle executor [{username_hash}]')
			await executor.close()
			cls.record_metric('executor_closed_idle')

	@classmethod
	async def get_executor(cls, username: str) -> LinuxDoConnectExecutor:
		username_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()[:8]
		await cls.sweep_idle_executors()
		async with cls._manager_lock:
			executor = cls._executors.get(username_hash)
			if executor is None:
				executor = LinuxDoConnectExecutor(username)
				cls._executors[username_hash] = executor
				print(f'ℹ️ LinuxDoConnectExecutorManager: created executor [{username_hash}]')
			else:
				cls.record_metric('executor_reused')
				print(f'ℹ️ LinuxDoConnectExecutorManager: reused executor [{username_hash}]')
			return executor

	@classmethod
	async def close_executor(cls, username: str):
		username_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()[:8]
		async with cls._manager_lock:
			executor = cls._executors.pop(username_hash, None)
		if executor is not None:
			await executor.close()

	@classmethod
	async def close_all(cls):
		async with cls._manager_lock:
			executors = list(cls._executors.values())
			cls._executors.clear()
		for executor in executors:
			await executor.close()
