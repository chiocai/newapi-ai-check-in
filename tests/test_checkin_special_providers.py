import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

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


def test_execute_check_in_short_circuits_when_status_checked_in(monkeypatch):
	account_config = build_account('wong')
	provider_config = ProviderConfig(
		name='wong',
		origin='https://wzw.pp.ua',
		sign_in_path='/api/user/checkin',
	)
	checkin = CheckIn('wong-1', account_config, provider_config)

	class DummyClient:
		def get(self, url, headers=None, timeout=None):
			return SimpleNamespace(status_code=200, text='{}')

		def post(self, url, headers=None, timeout=None):
			raise AssertionError('POST should not be called when status already checked_in')

	monkeypatch.setattr('checkin.response_resolve', lambda response, *_args: {'success': True, 'data': {'checked_in': True}})

	success, error_msg = checkin.execute_check_in(DummyClient(), {'New-API-User': '1'}, 1)

	assert success is True
	assert error_msg == ''


def test_check_in_with_cookies_falls_back_to_browser_manual_checkin(monkeypatch):
	account_config = build_account('wong')
	provider_config = ProviderConfig(
		name='wong',
		origin='https://wzw.pp.ua',
		sign_in_path='/api/user/checkin',
		user_info_path='/api/user/self',
	)
	checkin = CheckIn('wong-1', account_config, provider_config)

	class DummyClient:
		def __init__(self, *args, **kwargs):
			self.cookies = SimpleNamespace(update=lambda *_args, **_kwargs: None)

		def close(self):
			return None

	monkeypatch.setattr('checkin.httpx.Client', DummyClient)
	manual_calls = []
	monkeypatch.setattr(checkin, 'execute_check_in', lambda *_args, **_kwargs: manual_calls.append(True) or (False, 'HTTP 401'))
	monkeypatch.setattr(
		checkin,
		'execute_check_in_with_browser',
		lambda *_args, **_kwargs: asyncio.sleep(0, result=(True, '')),
	)
	monkeypatch.setattr(
		checkin,
		'get_user_info',
		lambda *_args, **_kwargs: asyncio.sleep(
			0,
			result={
				'success': True,
				'quota': 1,
				'used_quota': 0,
				'bonus_quota': 0,
				'display': 'ok',
			},
		),
	)

	success, user_info = asyncio.run(checkin.check_in_with_cookies({'session': 'abc'}, 1))

	assert manual_calls == [True]
	assert success is True
	assert user_info['success'] is True


def test_check_in_with_linuxdo_login_only_reauths_when_provider_cache_invalid(monkeypatch, tmp_path):
	account_config = build_account('alpha')
	provider_config = ProviderConfig(
		name='alpha',
		origin='https://alpha.example.com',
		sign_in_path=None,
		linuxdo_client_id='client-id',
	)
	checkin = CheckIn('alpha-1', account_config, provider_config, storage_state_dir=str(tmp_path))

	username = account_config.linux_do['username']
	username_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()[:8]
	cache_path = tmp_path / f'provider_alpha_{username_hash}_session.json'
	cache_path.write_text(json.dumps({
		'cookies': {'session': 'cached'},
		'api_user': '123',
		'timestamp': time.time(),
	}))

	async def fake_validate_provider_session(_cookies, _api_user):
		return {'success': False, 'error': 'Failed to get user info: HTTP 401'}

	async def fake_get_auth_state(*_args, **_kwargs):
		return {'success': True, 'state': 'state-1', 'cookies': []}

	class DummyLinuxDoSignIn:
		def __init__(self, *args, **kwargs):
			return None

		async def signin(self, **_kwargs):
			return True, {'cookies': {'session': 'fresh'}, 'api_user': '456'}

	monkeypatch.setattr(checkin, 'validate_provider_session', fake_validate_provider_session)
	monkeypatch.setattr(checkin, 'get_auth_state', fake_get_auth_state)
	monkeypatch.setattr('sign_in_with_linuxdo.LinuxDoSignIn', DummyLinuxDoSignIn)

	success, login_result = asyncio.run(
		checkin.check_in_with_linuxdo(
			username,
			account_config.linux_do['password'],
			{},
			login_only=True,
		)
	)

	assert success is True
	assert login_result == {'cookies': {'session': 'fresh'}, 'api_user': '456'}
	assert json.loads(cache_path.read_text(encoding='utf-8'))['api_user'] == '456'
