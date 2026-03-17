import json
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sync_storage_states_to_env import (
	load_accounts_from_env_file,
	sync_storage_states_into_accounts,
	write_accounts_to_env_file,
)


def test_sync_storage_states_into_accounts_merges_payload():
	accounts = {
		'linux.do': [],
		'accounts': [],
		'linuxdo_storage_states': {
			'linuxdo_old_storage_state.json': {'cookies': [{'name': 'old'}], 'origins': []},
		},
	}
	payload = {
		'linuxdo_new_storage_state.json': {'cookies': [{'name': 'new'}], 'origins': []},
	}

	updated = sync_storage_states_into_accounts(accounts, payload)

	assert updated['linuxdo_storage_states'] == {
		'linuxdo_old_storage_state.json': {'cookies': [{'name': 'old'}], 'origins': []},
		'linuxdo_new_storage_state.json': {'cookies': [{'name': 'new'}], 'origins': []},
	}


def test_write_accounts_to_env_file_updates_accounts_line(tmp_path):
	env_file = tmp_path / '.env'
	env_file.write_text(
		'FOO=bar\nACCOUNTS={"linux.do":[],"accounts":[],"linuxdo_storage_states":{}}\nBAR=baz\n',
		encoding='utf-8',
	)
	original_text, accounts, match = load_accounts_from_env_file(str(env_file))
	updated_accounts = sync_storage_states_into_accounts(
		accounts,
		{
			'linuxdo_demo_storage_state.json': {
				'cookies': [],
				'origins': [],
			},
			'provider_alpha_demo_session.json': {
				'cookies': {'session': 'abc'},
				'api_user': '1',
				'timestamp': 123,
			},
		},
	)

	write_accounts_to_env_file(str(env_file), original_text, match, updated_accounts)
	new_text = env_file.read_text(encoding='utf-8')

	assert 'FOO=bar' in new_text
	assert 'BAR=baz' in new_text
	accounts_line = next(line for line in new_text.splitlines() if line.startswith('ACCOUNTS='))
	parsed = json.loads(accounts_line[len('ACCOUNTS='):])
	assert parsed['linuxdo_storage_states']['linuxdo_demo_storage_state.json'] == {'cookies': [], 'origins': []}
	assert parsed['linuxdo_storage_states']['provider_alpha_demo_session.json'] == {
		'cookies': {'session': 'abc'},
		'api_user': '1',
		'timestamp': 123,
	}
