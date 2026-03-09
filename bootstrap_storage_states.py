#!/usr/bin/env python3
"""
从环境变量恢复预热好的 storage state 文件
"""

import argparse
import base64
import json
import os
from pathlib import Path

DEFAULT_STORAGE_DIR = 'storage-states'
DEFAULT_ENV_NAME = 'PREWARMED_STORAGE_STATES'
DEFAULT_B64_ENV_NAME = 'PREWARMED_STORAGE_STATES_B64'
DEFAULT_ACCOUNTS_ENV_NAME = 'ACCOUNTS'
DEFAULT_ACCOUNTS_KEY = 'linuxdo_storage_states'


def load_storage_states_payload(raw_payload: str | None = None, raw_payload_b64: str | None = None) -> dict:
	"""加载预热 storage states 配置"""
	payload_text = raw_payload_b64 or raw_payload or ''
	if not payload_text.strip():
		return {}

	if raw_payload_b64:
		payload_text = base64.b64decode(payload_text).decode('utf-8')

	payload = json.loads(payload_text)
	if not isinstance(payload, dict):
		raise RuntimeError('Prewarmed storage states must be a JSON object')
	return payload


def normalize_storage_state_entries(payload: dict) -> dict[str, dict | list]:
	"""规范化 payload 为可落盘的 JSON 结构"""
	normalized = {}
	for filename, content in payload.items():
		if not isinstance(filename, str) or not filename.endswith('.json'):
			raise RuntimeError(f'Invalid storage state filename: {filename!r}')
		if '/' in filename or '\\' in filename or '..' in filename:
			raise RuntimeError(f'Unsafe storage state filename: {filename!r}')

		if isinstance(content, str):
			content = json.loads(content)
		if not isinstance(content, (dict, list)):
			raise RuntimeError(f'Storage state content must be JSON object or array: {filename}')
		normalized[filename] = content
	return normalized


def restore_storage_states(payload: dict, storage_dir: str = DEFAULT_STORAGE_DIR, overwrite: bool = False) -> tuple[list[str], list[str]]:
	"""恢复 storage state 文件到本地目录"""
	storage_path = Path(storage_dir)
	storage_path.mkdir(parents=True, exist_ok=True)

	written = []
	skipped = []
	for filename, content in normalize_storage_state_entries(payload).items():
		target_path = storage_path / filename
		if target_path.exists() and not overwrite:
			skipped.append(filename)
			continue
		target_path.write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding='utf-8')
		written.append(filename)

	return written, skipped


def load_storage_states_from_accounts(accounts_payload: str | None, accounts_key: str = DEFAULT_ACCOUNTS_KEY) -> dict:
	"""从 ACCOUNTS 顶层字段提取预热 storage states"""
	if not accounts_payload:
		return {}

	accounts_data = json.loads(accounts_payload)
	if not isinstance(accounts_data, dict):
		return {}

	payload = accounts_data.get(accounts_key)
	if not isinstance(payload, dict):
		return {}

	return payload


def bootstrap_storage_states_from_accounts_env(
	accounts_env: str = DEFAULT_ACCOUNTS_ENV_NAME,
	accounts_key: str = DEFAULT_ACCOUNTS_KEY,
	storage_dir: str = DEFAULT_STORAGE_DIR,
	overwrite: bool = False,
) -> tuple[list[str], list[str]]:
	"""从 ACCOUNTS 环境变量恢复预热 storage states"""
	accounts_payload = os.getenv(accounts_env)
	payload = load_storage_states_from_accounts(accounts_payload, accounts_key=accounts_key)
	if not payload:
		return [], []
	return restore_storage_states(payload, storage_dir=storage_dir, overwrite=overwrite)


def main() -> int:
	parser = argparse.ArgumentParser(description='Restore prewarmed storage-states from environment secrets')
	parser.add_argument('--storage-dir', default=DEFAULT_STORAGE_DIR, help='Target storage directory')
	parser.add_argument('--env-name', default=DEFAULT_ENV_NAME, help='Raw JSON payload environment variable name')
	parser.add_argument('--env-name-b64', default=DEFAULT_B64_ENV_NAME, help='Base64 JSON payload environment variable name')
	parser.add_argument('--overwrite', action='store_true', help='Overwrite existing files')
	args = parser.parse_args()

	raw_payload = os.getenv(args.env_name)
	raw_payload_b64 = os.getenv(args.env_name_b64)
	if not raw_payload and not raw_payload_b64:
		print('ℹ️ No prewarmed storage states secret provided, skipping bootstrap')
		return 0

	payload = load_storage_states_payload(raw_payload, raw_payload_b64)
	if not payload:
		print('ℹ️ Prewarmed storage states payload is empty, skipping bootstrap')
		return 0

	written, skipped = restore_storage_states(payload, storage_dir=args.storage_dir, overwrite=args.overwrite)
	if written:
		print(f'✅ Restored {len(written)} storage state file(s): {written}')
	if skipped:
		print(f'ℹ️ Skipped {len(skipped)} existing storage state file(s): {skipped}')
	return 0


if __name__ == '__main__':
	raise SystemExit(main())
