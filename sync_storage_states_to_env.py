#!/usr/bin/env python3
"""
同步 storage-states 下的预热态 / 站点 session 到 .env 的 ACCOUNTS.linuxdo_storage_states
"""

import argparse
import json
import re
from pathlib import Path

from export_storage_states_secret import collect_storage_state_files

ACCOUNTS_LINE_RE = re.compile(r'^ACCOUNTS=(.*)$', re.MULTILINE)


def load_accounts_from_env_file(env_file: str) -> tuple[str, dict, re.Match[str]]:
	"""从 env 文件中读取 ACCOUNTS JSON"""
	env_path = Path(env_file)
	text = env_path.read_text(encoding='utf-8')
	match = ACCOUNTS_LINE_RE.search(text)
	if not match:
		raise RuntimeError(f'ACCOUNTS line not found in {env_path}')

	accounts = json.loads(match.group(1))
	if not isinstance(accounts, dict):
		raise RuntimeError('ACCOUNTS must be a JSON object')
	return text, accounts, match


def sync_storage_states_into_accounts(
	accounts: dict,
	payload: dict[str, dict | list],
	replace_all: bool = False,
) -> dict:
	"""将 storage state payload 合并回 ACCOUNTS"""
	updated = dict(accounts)
	if replace_all:
		updated['linuxdo_storage_states'] = dict(payload)
		return updated

	existing = updated.get('linuxdo_storage_states')
	if not isinstance(existing, dict):
		existing = {}

	existing.update(payload)
	updated['linuxdo_storage_states'] = existing
	return updated


def write_accounts_to_env_file(env_file: str, original_text: str, match: re.Match[str], accounts: dict) -> None:
	"""将更新后的 ACCOUNTS 回写到 env 文件"""
	new_accounts_line = 'ACCOUNTS=' + json.dumps(accounts, ensure_ascii=False, separators=(',', ':'))
	new_text = original_text[:match.start()] + new_accounts_line + original_text[match.end():]
	Path(env_file).write_text(new_text, encoding='utf-8')


def main() -> int:
	parser = argparse.ArgumentParser(description='Sync storage-states into ACCOUNTS.linuxdo_storage_states')
	parser.add_argument('--env-file', default='.env', help='Target env file path')
	parser.add_argument('--storage-dir', default='storage-states', help='Source storage directory')
	parser.add_argument('--include-provider-sessions', action='store_true', help='Also sync provider_*_session.json')
	parser.add_argument('--include-runtime', action='store_true', help='Also sync newapi-sites.runtime.json')
	parser.add_argument('--replace-all', action='store_true', help='Replace linuxdo_storage_states entirely instead of merging')
	args = parser.parse_args()

	payload = collect_storage_state_files(
		storage_dir=args.storage_dir,
		include_runtime=args.include_runtime,
		include_provider_sessions=args.include_provider_sessions,
	)
	if not payload:
		print('ℹ️ No storage state file found to sync')
		return 1

	original_text, accounts, match = load_accounts_from_env_file(args.env_file)
	updated_accounts = sync_storage_states_into_accounts(accounts, payload, replace_all=args.replace_all)
	write_accounts_to_env_file(args.env_file, original_text, match, updated_accounts)

	print(
		f'✅ Synced {len(payload)} storage state file(s) into {args.env_file}: '
		f'{sorted(payload.keys())}'
	)
	return 0


if __name__ == '__main__':
	raise SystemExit(main())
