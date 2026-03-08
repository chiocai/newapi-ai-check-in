import asyncio
import json
import sys
import time
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from checkin import CheckIn, _load_provider_session_cache
from utils.config import AccountConfig, ProviderConfig


def build_account(provider: str = 'dummy') -> AccountConfig:
	return AccountConfig.from_dict(
		{
			'name': 'dummy-account',
			'provider': provider,
			'linux.do': {
				'username': 'dummy-user',
				'password': 'dummy-pass',
			},
		},
		0,
	)


def build_provider(get_cdk):
	return ProviderConfig(
		name='dummy',
		origin='https://dummy.example.com',
		sign_in_path=None,
		topup_path=None,
		get_cdk=get_cdk,
	)


def test_execute_marks_empty_get_cdk_as_failure():
	account_config = build_account()
	provider_config = build_provider(lambda _account: None)
	checkin = CheckIn('dummy-account', account_config, provider_config)

	results = asyncio.run(checkin.execute())

	assert len(results) == 1
	auth_method, success, user_info = results[0]
	assert auth_method == 'linux.do'
	assert success is False
	assert user_info == {'error': 'get_cdk returned no result'}


def test_execute_keeps_structured_get_cdk_result_as_success():
	account_config = build_account()
	provider_config = build_provider(
		lambda _account: {
			'type': 'checkin_success',
			'quota': 75,
			'balance': 0,
		}
	)
	checkin = CheckIn('dummy-account', account_config, provider_config)

	results = asyncio.run(checkin.execute())

	assert len(results) == 1
	auth_method, success, user_info = results[0]
	assert auth_method == 'linux.do'
	assert success is True
	assert user_info == {
		'success': True,
		'cdk_results': [
			{
				'type': 'checkin_success',
				'quota': 75,
				'balance': 0,
			}
		],
	}


def test_load_provider_session_cache_returns_stale_cache(tmp_path):
	cache_path = tmp_path / 'provider_session.json'
	cache_path.write_text(json.dumps({
		'cookies': {'session': 'abc'},
		'api_user': '123',
		'timestamp': time.time() - (24 * 60 * 60),
	}))

	cache = _load_provider_session_cache(str(cache_path))

	assert cache is not None
	assert cache['cookies'] == {'session': 'abc'}
	assert cache['api_user'] == '123'
	assert cache['_stale'] is True
