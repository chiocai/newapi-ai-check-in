#!/usr/bin/env python3
"""
站点运行时自动发现与缓存
"""

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

import httpx
from camoufox.async_api import AsyncCamoufox

from utils.browser_utils import get_random_user_agent
from utils.config import AppConfig, ProviderConfig
from utils.http_utils import proxy_resolve

RUNTIME_SITES_PAYLOAD_VERSION = 1

LINUXDO_CLIENT_ID_PATTERN = re.compile(
	r'https://connect\.linux\.do/oauth2/authorize[^"\'>\s]*client_id=([^&"\'>\s]+)',
	re.IGNORECASE,
)
GITHUB_CLIENT_ID_PATTERN = re.compile(
	r'https://github\.com/login/oauth/authorize[^"\'>\s]*client_id=([^&"\'>\s]+)',
	re.IGNORECASE,
)
TURNSTILE_SITEKEY_PATTERNS = [
	re.compile(r'data-sitekey=["\']([^"\']+)["\']', re.IGNORECASE),
	re.compile(r'sitekey["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
]


def extract_runtime_overrides_from_status_payload(payload: dict | None) -> dict:
	"""从状态接口 JSON 中提取可缓存配置"""
	if not isinstance(payload, dict):
		return {}

	data = payload.get('data', payload)
	if not isinstance(data, dict):
		return {}

	overrides = {}
	linuxdo_client_id = data.get('linuxdo_client_id')
	if linuxdo_client_id:
		overrides['linuxdo_client_id'] = linuxdo_client_id

	github_client_id = data.get('github_client_id')
	if github_client_id:
		overrides['github_client_id'] = github_client_id

	turnstile_site_key = data.get('turnstile_site_key')
	if turnstile_site_key:
		overrides['turnstile_site_key'] = turnstile_site_key

	return overrides


def extract_runtime_overrides_from_text(text: str) -> dict:
	"""从 HTML / JS 文本中提取可缓存配置"""
	if not text:
		return {}

	overrides = {}

	linuxdo_match = LINUXDO_CLIENT_ID_PATTERN.search(text)
	if linuxdo_match:
		overrides['linuxdo_client_id'] = linuxdo_match.group(1)

	github_match = GITHUB_CLIENT_ID_PATTERN.search(text)
	if github_match:
		overrides['github_client_id'] = github_match.group(1)

	lower_text = text.lower()
	if any(keyword in lower_text for keyword in ['turnstile', 'cf-turnstile', 'challenges.cloudflare.com/turnstile']):
		for pattern in TURNSTILE_SITEKEY_PATTERNS:
			match = pattern.search(text)
			if match:
				overrides['turnstile_site_key'] = match.group(1)
				break

	return overrides


def load_runtime_sites_payload(runtime_sites_file: str | Path) -> dict:
	"""加载运行时站点缓存"""
	runtime_path = Path(runtime_sites_file)
	if not runtime_path.exists():
		return {'version': RUNTIME_SITES_PAYLOAD_VERSION, 'sites': {}}

	try:
		payload = json.loads(runtime_path.read_text(encoding='utf-8'))
		if isinstance(payload, dict) and isinstance(payload.get('sites'), dict):
			return payload
		if isinstance(payload, dict):
			return {'version': RUNTIME_SITES_PAYLOAD_VERSION, 'sites': payload}
	except Exception as exc:
		print(f'⚠️ Failed to read runtime sites payload {runtime_path}: {exc}')

	return {'version': RUNTIME_SITES_PAYLOAD_VERSION, 'sites': {}}


def save_runtime_sites_payload(runtime_sites_file: str | Path, payload: dict) -> None:
	"""保存运行时站点缓存"""
	runtime_path = Path(runtime_sites_file)
	runtime_path.parent.mkdir(parents=True, exist_ok=True)
	tmp_path = runtime_path.with_suffix(runtime_path.suffix + '.tmp')
	tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding='utf-8')
	tmp_path.replace(runtime_path)


def update_runtime_site_override(runtime_sites_file: str | Path, site_name: str, overrides: dict) -> dict:
	"""更新单个站点的运行时覆盖缓存"""
	payload = load_runtime_sites_payload(runtime_sites_file)
	sites = payload.setdefault('sites', {})
	entry = sites.setdefault(site_name, {})
	for key, value in overrides.items():
		if key.startswith('_'):
			continue
		if value == '':
			continue
		entry[key] = value
	entry['_updated_at'] = datetime.now().isoformat(timespec='seconds')
	save_runtime_sites_payload(runtime_sites_file, payload)
	return payload


def get_required_runtime_fields(app_config: AppConfig) -> dict[str, set[str]]:
	"""计算当前运行需要补齐的运行时字段"""
	required = {}
	for account in app_config.accounts:
		site_name = account.provider
		provider = app_config.get_provider(site_name)
		site_definition = app_config.site_definitions.get(site_name)
		if not provider or not site_definition:
			continue

		fields = required.setdefault(site_name, set())
		if account.linux_do and not provider.linuxdo_client_id:
			fields.add('linuxdo_client_id')
		if account.github and not provider.github_client_id:
			fields.add('github_client_id')
		if site_definition.mode == 'turnstile' and not provider.turnstile_site_key:
			fields.add('turnstile_site_key')

		if not fields:
			required.pop(site_name, None)

	return required


async def discover_status_runtime_overrides(provider_config: ProviderConfig, required_fields: Iterable[str], proxy: dict | None) -> dict:
	"""通过状态接口发现运行时字段"""
	fields = set(required_fields)
	if not fields.intersection({'linuxdo_client_id', 'github_client_id', 'turnstile_site_key'}):
		return {}
	if not provider_config.status_path:
		return {}

	headers = {
		'User-Agent': get_random_user_agent(),
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Accept-Encoding': 'gzip, deflate, br, zstd',
		'Referer': provider_config.get_login_url(),
		'Origin': provider_config.origin,
	}
	http_proxy = proxy_resolve(proxy)
	try:
		async with httpx.AsyncClient(http2=True, timeout=30.0, proxy=http_proxy) as client:
			response = await client.get(provider_config.get_status_url(), headers=headers)
			if response.status_code != 200:
				return {}
			return {
				key: value
				for key, value in extract_runtime_overrides_from_status_payload(response.json()).items()
				if key in fields and value
			}
	except Exception as exc:
		print(f'⚠️ Failed to discover status metadata for {provider_config.name}: {exc}')
		return {}


async def discover_browser_runtime_overrides(provider_config: ProviderConfig, required_fields: Iterable[str], proxy: dict | None) -> dict:
	"""通过浏览器探测页面内容并发现运行时字段"""
	fields = set(required_fields)
	if not fields:
		return {}

	target_urls = [
		provider_config.get_console_personal_url(),
		provider_config.get_login_url(),
		provider_config.origin,
	]
	seen_urls = set()
	discovered = {}

	async with AsyncCamoufox(
		headless=True,
		humanize=True,
		locale='en-US',
		geoip=True if proxy else False,
		proxy=proxy,
	) as browser:
		page = await browser.new_page()
		try:
			for target_url in target_urls:
				if target_url in seen_urls:
					continue
				seen_urls.add(target_url)
				try:
					print(f'ℹ️ Runtime discovery: opening {target_url}')
					await page.goto(target_url, wait_until='domcontentloaded', timeout=60000)
					await page.wait_for_timeout(3000)
				except Exception as exc:
					print(f'⚠️ Runtime discovery failed to open {target_url}: {exc}')
					continue

				try:
					status_str = await page.evaluate("() => localStorage.getItem('status')")
					if status_str:
						try:
							discovered.update(extract_runtime_overrides_from_status_payload(json.loads(status_str)))
						except Exception:
							pass
				except Exception:
					pass

				try:
					html = await page.content()
					discovered.update(extract_runtime_overrides_from_text(html))
				except Exception:
					pass

				if fields.issubset({key for key, value in discovered.items() if value}):
					break
		finally:
			await page.close()

	return {key: value for key, value in discovered.items() if key in fields and value}


async def ensure_runtime_site_overrides(app_config: AppConfig, max_concurrency: int = 10) -> dict[str, dict]:
	"""确保缺失的站点运行时配置已被自动发现并缓存"""
	required_map = get_required_runtime_fields(app_config)
	if not required_map:
		print('ℹ️ Runtime discovery skipped: no missing site metadata')
		return {}

	discovered_overrides = {}
	semaphore = asyncio.Semaphore(max_concurrency)

	async def discover_one(site_name: str, required_fields: set[str]) -> tuple[str, ProviderConfig | None, dict]:
		provider = app_config.get_provider(site_name)
		if not provider:
			return site_name, None, {}

		async with semaphore:
			print(f'🔎 Runtime discovery for {site_name}: {sorted(required_fields)}')
			overrides = await discover_status_runtime_overrides(provider, required_fields, app_config.global_proxy)
			missing_fields = required_fields - set(overrides)
			if missing_fields:
				overrides.update(await discover_browser_runtime_overrides(provider, missing_fields, app_config.global_proxy))

			if not overrides:
				print(f'⚠️ Runtime discovery found nothing for {site_name}')
			return site_name, provider, overrides

	results = await asyncio.gather(
		*(discover_one(site_name, required_fields) for site_name, required_fields in required_map.items())
	)

	for site_name, provider, overrides in results:
		if not provider or not overrides:
			continue
		update_runtime_site_override(app_config.runtime_sites_file, site_name, overrides)
		app_config.update_provider(site_name, provider.apply_overrides(overrides))
		discovered_overrides[site_name] = overrides
		print(f'✅ Runtime discovery saved for {site_name}: {sorted(overrides)}')

	return discovered_overrides
