#!/usr/bin/env python3
"""
按“先跑站点当前模式，失败后切换到相反 bypass 模式再重试一次”的策略，
批量测试指定 newapi 站点的签到可用性。

说明：
- 仅使用 ACCOUNTS 里的全局 `linux.do` 列表，忽略 `accounts` 与 `linuxdo_storage_states`
- 每个站点每个账号最多尝试 2 次：
  1) provider_config 当前 bypass 模式
  2) 与当前相反的 bypass 模式
- 第二次仅对第一次失败的账号执行
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from checkin import CheckIn
from utils.config import AppConfig, ProviderConfig
from utils.linuxdo_session import LinuxDoSessionManager


@dataclass
class AttemptResult:
	strategy: str
	bypass_method: str | None
	success: bool
	duration_seconds: float
	error_type: str | None = None
	error_summary: str | None = None
	error_detail: str | None = None
	error: str | None = None


@dataclass
class AccountToggleResult:
	account_name: str
	username: str
	attempts: list[AttemptResult] = field(default_factory=list)


@dataclass
class SiteToggleResult:
	site_name: str
	origin: str
	mode: str
	total_accounts: int
	success_accounts: int
	account_results: list[AccountToggleResult] = field(default_factory=list)
	recommend_mode: str | None = None


def _safe_text(value: Any) -> str:
	return '' if value is None else str(value)


def build_linuxdo_only_accounts_payload(raw_accounts: str) -> str:
	"""从 ACCOUNTS JSON 中提取全局 linux.do 列表，构造仅包含 linux.do 的 payload。"""
	data = json.loads(raw_accounts or '')
	if not isinstance(data, dict):
		raise RuntimeError('ACCOUNTS must be a JSON object')

	linuxdo_list = data.get('linux.do') or []
	if not isinstance(linuxdo_list, list) or not linuxdo_list:
		raise RuntimeError('ACCOUNTS.linux.do not found (or not a non-empty list)')

	filtered: list[dict] = []
	for item in linuxdo_list:
		if not isinstance(item, dict):
			continue
		username = item.get('username')
		password = item.get('password')
		if username and password:
			filtered.append({'username': username, 'password': password})

	if not filtered:
		raise RuntimeError('No valid linux.do credential found in ACCOUNTS.linux.do')

	return json.dumps({'linux.do': filtered, 'accounts': []}, ensure_ascii=False)


def build_provider_variant(base: ProviderConfig, bypass_method: str | None) -> ProviderConfig:
	"""基于 base provider 构造 bypass_method 覆盖版本（不落盘）。"""
	return base.apply_overrides({'bypass_method': bypass_method})


def get_toggled_bypass_method(current_bypass_method: str | None) -> str | None:
	"""根据当前 bypass_method 返回相反模式。"""
	return None if current_bypass_method == 'waf_cookies' else 'waf_cookies'


def build_mode_string(site_mode: str, provider_config: ProviderConfig) -> str:
	"""根据站点基础模式与当前 bypass 配置，生成可直接落回 sites.txt 的 mode 字符串。"""
	needs_waf = provider_config.needs_waf_cookies()
	sign_in_path = provider_config.sign_in_path

	if site_mode in {'newapi', 'newapi-waf'}:
		return 'newapi-waf' if needs_waf else 'newapi'
	if site_mode in {'auto', 'auto-waf'}:
		return 'auto-waf' if needs_waf else 'auto'
	if site_mode in {'manual', 'manual-waf'}:
		path = sign_in_path if isinstance(sign_in_path, str) and sign_in_path else '/api/user/sign_in'
		prefix = 'manual-waf' if needs_waf else 'manual'
		return f'{prefix}:{path}'
	return site_mode


def resolve_recommend_mode(
	account_results: list[AccountToggleResult],
	base_mode: str,
	toggled_mode: str,
) -> str | None:
	"""根据两轮结果给出建议模式。"""
	if not account_results:
		return None

	base_all_success = all(item.attempts and item.attempts[0].success for item in account_results)
	toggled_all_success = all(
		len(item.attempts) >= 2 and item.attempts[1].success
		for item in account_results
	)

	if base_all_success:
		return base_mode
	if toggled_all_success:
		return toggled_mode
	return None


async def run_checkin_once(
	account_index: int,
	account_config,
	app_config: AppConfig,
	provider_config: ProviderConfig,
	semaphore: asyncio.Semaphore,
	strategy: str,
	bypass_method: str | None,
) -> tuple[bool, AttemptResult]:
	"""执行一次签到尝试，返回 (是否成功, AttemptResult)。"""
	async with semaphore:
		account_name = account_config.get_display_name(account_index)
		username = ''
		try:
			if account_config.linux_do:
				username = (account_config.linux_do or {}).get('username') or ''
		except Exception:
			username = ''

		if username:
			# 避免某次失败导致全局熔断，影响后续重试
			LinuxDoSessionManager.clear_circuit(username)

		checkin = CheckIn(
			account_name=account_name,
			account_config=account_config,
			provider_config=provider_config,
			global_proxy=app_config.global_proxy,
			linuxdo_session=None,
		)

		start = time.time()
		try:
			results = await checkin.execute()
		except Exception as exc:
			duration = time.time() - start
			payload = AttemptResult(
				strategy=strategy,
				bypass_method=bypass_method,
				success=False,
				duration_seconds=duration,
				error_summary=_safe_text(exc)[:120],
				error=_safe_text(exc),
			)
			return False, payload

		duration = time.time() - start

		success = False
		first_error: dict[str, Any] | None = None
		for _, method_ok, user_info in results:
			if method_ok and isinstance(user_info, dict) and user_info.get('success'):
				success = True
				break
			if first_error is None and isinstance(user_info, dict):
				first_error = user_info

		payload = AttemptResult(
			strategy=strategy,
			bypass_method=bypass_method,
			success=success,
			duration_seconds=duration,
			error_type=(first_error or {}).get('error_type'),
			error_summary=(first_error or {}).get('error_summary'),
			error_detail=(first_error or {}).get('error_detail'),
			error=(first_error or {}).get('error'),
		)
		return success, payload


async def main() -> int:
	parser = argparse.ArgumentParser(description='Try current bypass mode then toggled fallback for selected sites')
	parser.add_argument('--sites-file', required=True, help='Path to a sites.txt (name | origin | mode)')
	parser.add_argument('--concurrency', type=int, default=2, help='Max concurrent account runs')
	parser.add_argument('--output', default='', help='Output JSON report path (default: logs/site_waf_toggle.<ts>.json)')
	args = parser.parse_args()

	load_dotenv(override=True)

	raw_accounts = os.getenv('ACCOUNTS')
	if not raw_accounts:
		print('❌ ACCOUNTS environment variable not found')
		return 2

	try:
		os.environ['ACCOUNTS'] = build_linuxdo_only_accounts_payload(raw_accounts)
	except Exception as exc:
		print(f'❌ Failed to build linux.do only ACCOUNTS payload: {_safe_text(exc)}')
		return 2

	# 避免无意义的报错输出；provider 主要来自 TXT
	os.environ.setdefault('PROVIDERS', '{}')
	os.environ['NEWAPI_SITES_FILE'] = args.sites_file

	app_config = AppConfig.load_from_env()
	if not app_config.accounts:
		print('❌ No accounts expanded from sites-file + linux.do list')
		return 2

	# 按站点分组账号（保留 index，便于拿到 display_name）
	site_to_accounts: dict[str, list[tuple[int, Any]]] = {}
	for index, account in enumerate(app_config.accounts):
		site_to_accounts.setdefault(account.provider, []).append((index, account))

	semaphore = asyncio.Semaphore(max(1, args.concurrency))
	results: list[SiteToggleResult] = []

	print(f'⚙️ Sites: {len(site_to_accounts)} | Accounts: {len(app_config.accounts)} | concurrency={args.concurrency}')

	for site_name, account_items in site_to_accounts.items():
		base_provider = app_config.get_provider(site_name)
		site_def = app_config.site_definitions.get(site_name)
		if not base_provider or not site_def:
			continue

		origin = base_provider.origin
		mode = site_def.mode
		base_mode_string = build_mode_string(site_def.mode, base_provider)
		toggled_bypass_method = get_toggled_bypass_method(base_provider.bypass_method)
		toggled_provider = build_provider_variant(base_provider, toggled_bypass_method)
		toggled_mode_string = build_mode_string(site_def.mode, toggled_provider)

		print(f'\n🧪 {site_name}: 当前 {base_mode_string} → 失败切换 {toggled_mode_string}')

		account_results: list[AccountToggleResult] = []
		# attempt #1: current mode
		current_provider = build_provider_variant(base_provider, base_provider.bypass_method)

		attempt1_tasks = []
		for account_index, account_config in account_items:
			username = ''
			try:
				if account_config.linux_do:
					username = (account_config.linux_do or {}).get('username') or ''
			except Exception:
				username = ''
			account_results.append(AccountToggleResult(account_name=account_config.get_display_name(account_index), username=username))
			attempt1_tasks.append(
				run_checkin_once(
					account_index,
					account_config,
					app_config,
					current_provider,
					semaphore,
					strategy=base_mode_string,
					bypass_method=current_provider.bypass_method,
				)
			)

		attempt1_outcomes = await asyncio.gather(*attempt1_tasks)
		failed_indices: list[int] = []
		for idx, (ok, attempt) in enumerate(attempt1_outcomes):
			account_results[idx].attempts.append(attempt)
			if not ok:
				failed_indices.append(idx)

		# attempt #2: toggled mode for failed accounts only
		if failed_indices:
			attempt2_tasks = []
			attempt2_map: list[int] = []
			for idx in failed_indices:
				account_index, account_config = account_items[idx]
				attempt2_map.append(idx)
				attempt2_tasks.append(
					run_checkin_once(
						account_index,
						account_config,
						app_config,
						toggled_provider,
						semaphore,
						strategy=toggled_mode_string,
						bypass_method=toggled_provider.bypass_method,
					)
				)

			attempt2_outcomes = await asyncio.gather(*attempt2_tasks)
			for idx, (ok, attempt) in zip(attempt2_map, attempt2_outcomes):
				account_results[idx].attempts.append(attempt)

		success_accounts = 0
		for item in account_results:
			if any(attempt.success for attempt in item.attempts):
				success_accounts += 1

		recommend_mode = resolve_recommend_mode(
			account_results=account_results,
			base_mode=base_mode_string,
			toggled_mode=toggled_mode_string,
		)

		print(f'📊 {site_name}: {success_accounts}/{len(account_results)} 账号成功（含回退）')

		results.append(
			SiteToggleResult(
				site_name=site_name,
				origin=origin,
				mode=mode,
				total_accounts=len(account_results),
				success_accounts=success_accounts,
				account_results=account_results,
				recommend_mode=recommend_mode,
			)
		)

	ts = datetime.now().strftime('%Y%m%d_%H%M%S')
	output_path = Path(args.output) if args.output else Path('logs') / f'site_waf_toggle.{ts}.json'
	output_path.parent.mkdir(parents=True, exist_ok=True)
	output_payload = {
		'generated_at': datetime.now().isoformat(timespec='seconds'),
		'sites_file': args.sites_file,
		'concurrency': args.concurrency,
		'sites': [
			{
				**asdict(site),
				'account_results': [
					{
						'account_name': acc.account_name,
						'username': acc.username,
						'attempts': [asdict(a) for a in acc.attempts],
					}
					for acc in site.account_results
				],
			}
			for site in results
		],
	}
	output_path.write_text(json.dumps(output_payload, ensure_ascii=False, indent=2), encoding='utf-8')

	print(f'\n✅ Report written: {output_path}')

	# stdout 总结：哪些站点可恢复
	recovered = [s for s in results if s.success_accounts > 0]
	full_ok = [s for s in results if s.success_accounts == s.total_accounts]
	print(f'📌 可恢复站点（至少 1 个账号成功）: {len(recovered)}/{len(results)}')
	print(f'📌 全账号成功站点: {len(full_ok)}/{len(results)}')

	if full_ok:
		print('\n--- 全账号成功（建议模式） ---')
		for site in full_ok:
			print(f"- {site.site_name} | {site.origin} | recommend={site.recommend_mode}")

	failed_sites = [s for s in results if s.success_accounts == 0]
	if failed_sites:
		print('\n--- 仍失败（两种策略都失败） ---')
		for site in failed_sites:
			print(f"- {site.site_name} | {site.origin}")

	return 0


if __name__ == '__main__':
	raise SystemExit(asyncio.run(main()))
