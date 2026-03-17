#!/usr/bin/env python3
"""
导出 GitHub Secret 可用的预热 storage states payload
"""

import argparse
import json
from pathlib import Path

DEFAULT_STORAGE_DIR = 'storage-states'


def collect_storage_state_files(
	storage_dir: str = DEFAULT_STORAGE_DIR,
	include_runtime: bool = False,
	include_provider_sessions: bool = False,
) -> dict[str, dict]:
	"""收集可用于 GitHub Secret 的 storage state 文件"""
	storage_path = Path(storage_dir)
	if not storage_path.exists():
		return {}

	payload = {}
	for path in sorted(storage_path.glob('linuxdo_*_storage_state.json')):
		payload[path.name] = json.loads(path.read_text(encoding='utf-8'))

	if include_provider_sessions:
		for path in sorted(storage_path.glob('provider_*_session.json')):
			payload[path.name] = json.loads(path.read_text(encoding='utf-8'))

	if include_runtime:
		runtime_file = storage_path / 'newapi-sites.runtime.json'
		if runtime_file.exists():
			payload[runtime_file.name] = json.loads(runtime_file.read_text(encoding='utf-8'))

	return payload


def main() -> int:
	parser = argparse.ArgumentParser(description='Export prewarmed storage-states payload for GitHub Secrets')
	parser.add_argument('--storage-dir', default=DEFAULT_STORAGE_DIR, help='Source storage directory')
	parser.add_argument('--include-runtime', action='store_true', help='Include newapi-sites.runtime.json in payload')
	parser.add_argument('--include-provider-sessions', action='store_true', help='Include provider_*_session.json in payload')
	args = parser.parse_args()

	payload = collect_storage_state_files(
		args.storage_dir,
		include_runtime=args.include_runtime,
		include_provider_sessions=args.include_provider_sessions,
	)
	if not payload:
		print('{}')
		return 1

	print(json.dumps(payload, ensure_ascii=False, separators=(',', ':')))
	return 0


if __name__ == '__main__':
	raise SystemExit(main())
