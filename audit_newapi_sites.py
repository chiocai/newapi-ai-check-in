#!/usr/bin/env python3
"""
审计 newapi-sites.txt 内站点签到可用性，并产出可清理的失效站点列表。

设计目标：
- 不依赖 main.py（避免 import 时自动 bootstrap storage states）
- 只使用 ACCOUNTS 里的全局 `linux.do` 列表，忽略 `accounts` 与 `linuxdo_storage_states`
- 对每个站点执行一次完整的签到流程（含 New-API checkin）
- 对全失败的站点做一次轻量探测，尽量只删除“确定失效”（域名不可达/根路径 404/410 等）的站点

输出：
- logs/newapi_sites_audit.<timestamp>.json：完整审计结果
- stdout：清理建议（dead_sites / suspicious_sites）
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

from checkin import CheckIn
from utils.config import AppConfig
from utils.linuxdo_session import LinuxDoSessionManager
from utils.site_discovery import ensure_runtime_site_overrides


@dataclass
class ProbeResult:
	url: str
	ok: bool
	status_code: int | None = None
	error: str | None = None


@dataclass
class AccountRunResult:
	site_name: str
	site_origin: str
	account_name: str
	success: bool
	error_type: str | None = None
	error_summary: str | None = None
	error_detail: str | None = None
	error: str | None = None
	raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class SiteAuditResult:
	site_name: str
	site_origin: str
	mode: str
	account_results: list[AccountRunResult]
	success_accounts: int
	total_accounts: int
	probes: list[ProbeResult] = field(default_factory=list)
	is_dead: bool = False
	dead_reason: str | None = None


def _safe_error_text(value: Any) -> str:
	text = '' if value is None else str(value)
	return re.sub(r'\\s+', ' ', text).strip()


def build_linuxdo_only_accounts_payload(raw_accounts: str) -> str:
	"""从原始 ACCOUNTS JSON 中提取全局 linux.do 列表，构造仅包含 linux.do 的 payload。"""
	data = json.loads(raw_accounts or '')
	if not isinstance(data, dict):
		raise RuntimeError('ACCOUNTS must be a JSON object to run audit script')

	linuxdo_list = data.get('linux.do') or []
	if not isinstance(linuxdo_list, list) or not linuxdo_list:
		raise RuntimeError('ACCOUNTS.linux.do not found (or not a non-empty list)')

	filtered = []
	for item in linuxdo_list:
		if not isinstance(item, dict):
			continue
		username = item.get('username')
		password = item.get('password')
		if username and password:
			filtered.append({'username': username, 'password': password})

	if not filtered:
		raise RuntimeError('No valid linux.do credential found in ACCOUNTS.linux.do')

	payload = {
		'linux.do': filtered,
		'accounts': [],
	}
	return json.dumps(payload, ensure_ascii=False)


async def probe_site_urls(urls: list[str], timeout_seconds: float = 15.0) -> list[ProbeResult]:
	"""轻量探测站点可达性：只做 GET，不带鉴权。"""
	results: list[ProbeResult] = []
	async with httpx.AsyncClient(http2=True, follow_redirects=True, timeout=timeout_seconds) as client:
		for url in urls:
			try:
				resp = await client.get(url, headers={'User-Agent': 'newapi-sites-audit/1.0'})
				results.append(ProbeResult(url=url, ok=True, status_code=resp.status_code))
			except Exception as exc:
				results.append(ProbeResult(url=url, ok=False, error=_safe_error_text(exc)))
	return results


def classify_dead_site(probes: list[ProbeResult]) -> tuple[bool, str | None]:
	"""根据 probe 结果判断站点是否“确定失效”。

策略（保守）：
- 只要根路径（origin）能拿到任意 HTTP 响应（含 403/5xx），就认为站点可达，不删除
- 根路径返回 404/410，或根路径出现明确的 DNS/连接失败/证书错误，判定为失效
"""
	if not probes:
		return False, None

	root = probes[0]
	if root.ok:
		if root.status_code in {404, 410}:
			return True, f'origin 返回 HTTP {root.status_code}'
		return False, None

	err = (root.error or '').lower()
	hard_errors = [
		'no address associated with hostname',
		'name or service not known',
		'nodename nor servname provided',
		'temporary failure in name resolution',
		'getaddrinfo failed',
		'connection refused',
		'network is unreachable',
		'no route to host',
		'certificate verify failed',
		'ssl',
		'connecterror',
		'all connection attempts failed',
	]
	if any(token in err for token in hard_errors):
		return True, f'origin 不可达: {root.error}'

	# 超时/429/高负载等不作为“确定失效”，避免误删
	return False, None


async def run_single_account(
	index: int,
	account_config,
	app_config: AppConfig,
	semaphore: asyncio.Semaphore,
) -> AccountRunResult:
	async with semaphore:
		# 审计场景下不希望单次失败触发全局熔断，避免后续站点被 linuxdo_circuit_open 误伤
		linuxdo_username = None
		if getattr(account_config, 'linux_do', None):
			try:
				linuxdo_username = (account_config.linux_do or {}).get('username')
			except Exception:
				linuxdo_username = None
		if linuxdo_username:
			LinuxDoSessionManager.clear_circuit(linuxdo_username)

		account_name = account_config.get_display_name(index)
		provider_name = account_config.provider
		provider_config = app_config.get_provider(provider_name)
		if not provider_config:
			return AccountRunResult(
				site_name=provider_name,
				site_origin='',
				account_name=account_name,
				success=False,
				error_summary='Provider configuration not found',
				error='Provider configuration not found',
			)

		checkin = CheckIn(
			account_name,
			account_config,
			provider_config,
			global_proxy=app_config.global_proxy,
			linuxdo_session=None,
		)

		try:
			results = await checkin.execute()
		except Exception as exc:
			return AccountRunResult(
				site_name=provider_name,
				site_origin=provider_config.origin,
				account_name=account_name,
				success=False,
				error_summary=_safe_error_text(exc)[:120],
				error=_safe_error_text(exc),
			)

		# execute() 返回多种认证方式的结果；本脚本默认仅跑 linux.do
		# 这里按“任意方法成功且 user_info.success”为账号成功
		success = False
		first_error: dict[str, Any] | None = None
		for _, method_ok, user_info in results:
			if method_ok and isinstance(user_info, dict) and user_info.get('success'):
				success = True
				break
			if first_error is None and isinstance(user_info, dict):
				first_error = user_info

		error_type = (first_error or {}).get('error_type')
		error_summary = (first_error or {}).get('error_summary')
		error_detail = (first_error or {}).get('error_detail')
		error = (first_error or {}).get('error')

		return AccountRunResult(
			site_name=provider_name,
			site_origin=provider_config.origin,
			account_name=account_name,
			success=success,
			error_type=error_type,
			error_summary=error_summary,
			error_detail=error_detail,
			error=error,
			raw={'results': results, 'first_error': first_error},
		)


async def main() -> int:
	parser = argparse.ArgumentParser(description='Audit newapi-sites.txt check-in availability')
	parser.add_argument('--sites-file', default='newapi-sites.txt', help='Path to newapi-sites.txt')
	parser.add_argument('--concurrency', type=int, default=2, help='Max concurrent account runs')
	parser.add_argument('--runtime-discovery', action='store_true', help='Run runtime discovery before audit')
	parser.add_argument('--no-runtime-discovery', dest='runtime_discovery', action='store_false')
	parser.set_defaults(runtime_discovery=True)
	parser.add_argument('--probe-timeout', type=float, default=15.0, help='Probe timeout seconds')
	args = parser.parse_args()

	load_dotenv(override=True)

	raw_accounts = os.getenv('ACCOUNTS')
	if not raw_accounts:
		print('❌ ACCOUNTS environment variable not found')
		return 2

	try:
		os.environ['ACCOUNTS'] = build_linuxdo_only_accounts_payload(raw_accounts)
	except Exception as exc:
		print(f'❌ Failed to build linux.do only ACCOUNTS payload: {_safe_error_text(exc)}')
		return 2

	# 避免无意义的报错输出；站点 provider 主要来自 TXT
	os.environ.setdefault('PROVIDERS', '{}')
	os.environ['NEWAPI_SITES_FILE'] = args.sites_file

	app_config = AppConfig.load_from_env()
	if not app_config.accounts:
		print('❌ No accounts generated from NEWAPI sites file + linux.do list')
		return 2

	print(f'⚙️ Sites loaded: {len(app_config.site_definitions)}')
	print(f'⚙️ Accounts expanded: {len(app_config.accounts)} (concurrency={args.concurrency})')

	if args.runtime_discovery:
		discovered = await ensure_runtime_site_overrides(app_config, max_concurrency=max(1, min(4, args.concurrency)))
		if discovered:
			print(f'⚙️ Runtime site overrides updated for {len(discovered)} site(s)')

	semaphore = asyncio.Semaphore(max(1, args.concurrency))
	tasks = [
		run_single_account(index, account_config, app_config, semaphore)
		for index, account_config in enumerate(app_config.accounts)
	]
	account_results = await asyncio.gather(*tasks)

	by_site: dict[str, list[AccountRunResult]] = {}
	for item in account_results:
		by_site.setdefault(item.site_name, []).append(item)

	site_audits: list[SiteAuditResult] = []
	suspicious_sites: list[dict[str, Any]] = []
	dead_sites: list[dict[str, Any]] = []

	for site_name, runs in sorted(by_site.items(), key=lambda x: x[0]):
		site_def = app_config.site_definitions.get(site_name)
		mode = site_def.mode if site_def else 'unknown'
		origin = runs[0].site_origin if runs else (site_def.provider.origin if site_def else '')

		success_accounts = sum(1 for r in runs if r.success)
		audit = SiteAuditResult(
			site_name=site_name,
			site_origin=origin,
			mode=mode,
			account_results=runs,
			success_accounts=success_accounts,
			total_accounts=len(runs),
		)

		# 全失败才做探测与分类
		if success_accounts == 0:
			urls = [
				origin,
				f'{origin}/login',
				f'{origin}/api/status',
			]
			audit.probes = await probe_site_urls(urls, timeout_seconds=args.probe_timeout)
			is_dead, reason = classify_dead_site(audit.probes)
			audit.is_dead = is_dead
			audit.dead_reason = reason

			suspicious_sites.append(
				{
					'site_name': site_name,
					'origin': origin,
					'mode': mode,
					'dead': is_dead,
					'dead_reason': reason,
					'errors': [
						{
							'account': r.account_name,
							'error_type': r.error_type,
							'error_summary': r.error_summary,
							'error_detail': r.error_detail,
							'error': r.error,
						}
						for r in runs
					],
					'probes': [asdict(p) for p in audit.probes],
				}
			)
			if is_dead:
				dead_sites.append({'site_name': site_name, 'origin': origin, 'mode': mode, 'reason': reason})

		site_audits.append(audit)

	timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
	output_path = Path('logs') / f'newapi_sites_audit.{timestamp}.json'
	output_path.parent.mkdir(parents=True, exist_ok=True)
	output_payload = {
		'generated_at': datetime.now().isoformat(timespec='seconds'),
		'sites_file': args.sites_file,
		'total_sites': len(site_audits),
		'total_accounts': len(app_config.accounts),
		'dead_sites': dead_sites,
		'suspicious_sites': suspicious_sites,
		'sites': [
			{
				'site_name': s.site_name,
				'origin': s.site_origin,
				'mode': s.mode,
				'success_accounts': s.success_accounts,
				'total_accounts': s.total_accounts,
				'is_dead': s.is_dead,
				'dead_reason': s.dead_reason,
				'account_results': [
					{
						'account_name': r.account_name,
						'success': r.success,
						'error_type': r.error_type,
						'error_summary': r.error_summary,
						'error_detail': r.error_detail,
						'error': r.error,
					}
					for r in s.account_results
				],
				'probes': [asdict(p) for p in s.probes],
			}
			for s in site_audits
		],
	}
	output_path.write_text(json.dumps(output_payload, ensure_ascii=False, indent=2), encoding='utf-8')

	print(f'✅ Audit report written: {output_path}')
	print(f'📊 Dead sites: {len(dead_sites)} | All-failed sites: {len(suspicious_sites)} | Total sites: {len(site_audits)}')

	if dead_sites:
		print('\n--- dead_sites (建议从 newapi-sites.txt 移除) ---')
		for item in dead_sites:
			print(f"- {item['site_name']} | {item['origin']} | {item['mode']} | {item['reason']}")

	if suspicious_sites and not dead_sites:
		print('\n--- suspicious_sites (全失败但未判定为确定失效) ---')
		for item in suspicious_sites[:20]:
			print(f"- {item['site_name']} | {item['origin']} | {item['mode']}")
		if len(suspicious_sites) > 20:
			print(f'... and {len(suspicious_sites) - 20} more')

	return 0


if __name__ == '__main__':
	raise SystemExit(asyncio.run(main()))
