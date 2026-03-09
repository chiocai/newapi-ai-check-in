import json
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from bootstrap_storage_states import (
	bootstrap_storage_states_from_accounts_env,
	load_storage_states_payload,
	restore_storage_states,
)
from export_storage_states_secret import collect_storage_state_files


def test_load_storage_states_payload_accepts_json_object():
	payload = load_storage_states_payload('{"linuxdo_demo_storage_state.json":{"cookies":[],"origins":[]}}')

	assert payload == {
		'linuxdo_demo_storage_state.json': {
			'cookies': [],
			'origins': [],
		}
	}


def test_restore_storage_states_writes_and_skips_existing(tmp_path):
	payload = {
		'linuxdo_demo_storage_state.json': {
			'cookies': [],
			'origins': [],
		}
	}

	written, skipped = restore_storage_states(payload, storage_dir=str(tmp_path))

	assert written == ['linuxdo_demo_storage_state.json']
	assert skipped == []

	written, skipped = restore_storage_states(payload, storage_dir=str(tmp_path))

	assert written == []
	assert skipped == ['linuxdo_demo_storage_state.json']


def test_collect_storage_state_files_reads_linuxdo_files(tmp_path):
	(tmp_path / 'linuxdo_demo_storage_state.json').write_text(
		json.dumps({'cookies': [], 'origins': []}),
		encoding='utf-8',
	)
	(tmp_path / 'provider_anyrouter_demo_session.json').write_text('{}', encoding='utf-8')

	payload = collect_storage_state_files(str(tmp_path))

	assert payload == {
		'linuxdo_demo_storage_state.json': {
			'cookies': [],
			'origins': [],
		}
	}


def test_bootstrap_storage_states_from_accounts_env(monkeypatch, tmp_path):
	monkeypatch.setenv(
		'ACCOUNTS',
		json.dumps(
			{
				'linux.do': [],
				'accounts': [],
				'linuxdo_storage_states': {
					'linuxdo_demo_storage_state.json': {
						'cookies': [],
						'origins': [],
					}
				},
			},
			ensure_ascii=False,
		),
	)

	written, skipped = bootstrap_storage_states_from_accounts_env(storage_dir=str(tmp_path))

	assert written == ['linuxdo_demo_storage_state.json']
	assert skipped == []
