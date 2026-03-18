import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sign_in_with_linuxdo import (
	LinuxDoSignIn,
	_diagnose_linuxdo_page_issue,
	_extract_sso_provider_redirect_candidates,
)
from utils.linuxdo_session import LinuxDoSession


def test_diagnose_linuxdo_page_issue_prefers_sso_provider_over_high_load(monkeypatch):
	class DummyPage:
		url = 'https://linux.do/session/sso_provider?foo=bar'

	async def fake_detect_linuxdo_page_guard(_page):
		return {
			'high_load': True,
			'human_verification': False,
			'cloudflare_challenge': False,
			'human_verification_sitekey': None,
		}

	monkeypatch.setattr('sign_in_with_linuxdo.detect_linuxdo_page_guard', fake_detect_linuxdo_page_guard)

	result = asyncio.run(_diagnose_linuxdo_page_issue(DummyPage()))

	assert result['error_type'] == 'linuxdo_sso_provider_stuck'
	assert result['error_summary'] == 'Linux.do SSO 中转页卡住'


def test_linuxdo_signin_does_not_retry_with_fresh_login_after_sso_provider_stuck(tmp_path):
	provider = SimpleNamespace(origin='https://anyrouter.top')
	signin = LinuxDoSignIn('anyrouter-1', provider, 'user', 'pass')
	call_count = []
	cache_file = tmp_path / 'storage.json'
	cache_file.write_text('{}')

	async def fake_signin_impl(client_id, auth_state, auth_cookies, cache_file_path=''):
		call_count.append((client_id, auth_state, cache_file_path))
		return False, {
			'error_type': 'linuxdo_sso_provider_stuck',
			'error_summary': 'Linux.do SSO 中转页卡住',
			'error_detail': 'Linux.do SSO provider page is stuck after cache restore',
			'error': 'Linux.do SSO provider page is stuck after cache restore',
		}

	signin._signin_impl = fake_signin_impl

	success, payload = asyncio.run(signin.signin('client-id', 'state-1', [], str(cache_file)))

	assert success is False
	assert payload['error_type'] == 'linuxdo_sso_provider_stuck'
	assert call_count == [('client-id', 'state-1', str(cache_file))]


def test_linuxdo_signin_does_not_retry_same_state_on_generic_failure():
	provider = SimpleNamespace(origin='https://alpha.example.com')
	signin = LinuxDoSignIn('alpha-1', provider, 'user', 'pass')
	call_count = []

	async def fake_signin_impl(client_id, auth_state, auth_cookies, cache_file_path=''):
		call_count.append((client_id, auth_state))
		return False, {
			'error_type': 'linuxdo_signin_failed',
			'error_summary': 'Generic failure',
			'error_detail': 'Generic failure',
			'error': 'Generic failure',
		}

	signin._signin_impl = fake_signin_impl

	success, payload = asyncio.run(signin.signin('client-id', 'state-1', [], ''))

	assert success is False
	assert payload['error_type'] == 'linuxdo_signin_failed'
	assert call_count == [('client-id', 'state-1')]


def test_resolve_storage_state_skips_shared_cache_when_session_not_logged_in(tmp_path):
	provider = SimpleNamespace(origin='https://anyrouter.top')
	cache_file = tmp_path / 'linuxdo_cache.json'
	cache_file.write_text('{}')
	shared_state_calls = []

	class DummySharedSession:
		is_logged_in = False

		async def get_storage_state(self):
			shared_state_calls.append('get_storage_state')
			return {'cookies': []}

		def get_storage_state_path(self):
			return str(cache_file)

	signin = LinuxDoSignIn('anyrouter-1', provider, 'user', 'pass', shared_session=DummySharedSession())

	result = asyncio.run(signin._resolve_storage_state(str(cache_file)))

	assert result == str(cache_file)
	assert shared_state_calls == []


def test_extract_sso_provider_redirect_candidates_from_script():
	html = """
	<html>
	<script>
	window.location.href = "https://connect.linux.do/discourse/sso_callback?sso=abc&sig=def";
	</script>
	</html>
	"""

	result = _extract_sso_provider_redirect_candidates(
		html,
		'https://linux.do/session/sso_provider?sig=x&sso=y',
		'https://anyrouter.top',
	)

	assert result == ['https://connect.linux.do/discourse/sso_callback?sso=abc&sig=def']


def test_extract_sso_provider_redirect_candidates_from_meta_refresh():
	html = """
	<html>
	<meta http-equiv="refresh" content="0;url=/oauth2/authorize?foo=bar">
	</html>
	"""

	result = _extract_sso_provider_redirect_candidates(
		html,
		'https://connect.linux.do/discourse/sso_callback',
		'https://anyrouter.top',
	)

	assert result == ['https://connect.linux.do/oauth2/authorize?foo=bar']


def test_linuxdo_session_ensure_logged_in_does_not_auto_login_without_prewarmed_cache(monkeypatch, tmp_path):
	session = LinuxDoSession('user', 'pass')
	session.storage_state_path = str(tmp_path / 'missing.json')
	login_calls = []

	async def fake_do_login():
		login_calls.append('called')
		return True

	monkeypatch.setattr(session, '_do_login', fake_do_login)

	result = asyncio.run(session.ensure_logged_in())

	assert result is False
	assert session.is_logged_in is False
	assert login_calls == []
