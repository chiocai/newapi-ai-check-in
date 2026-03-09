import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sign_in_with_linuxdo import LinuxDoSignIn, _diagnose_linuxdo_page_issue


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


def test_linuxdo_signin_retries_once_with_fresh_login_after_sso_provider_stuck():
	provider = SimpleNamespace(origin='https://anyrouter.top')
	signin = LinuxDoSignIn('anyrouter-1', provider, 'user', 'pass')
	call_force_fresh_login = []

	async def fake_signin_impl(client_id, auth_state, auth_cookies, cache_file_path='', force_fresh_login=False):
		call_force_fresh_login.append(force_fresh_login)
		if not force_fresh_login:
			return False, {
				'error_type': 'linuxdo_sso_provider_stuck',
				'error_summary': 'Linux.do SSO 中转页卡住',
				'error_detail': 'Linux.do SSO provider page is stuck after cache restore',
				'error': 'Linux.do SSO provider page is stuck after cache restore',
			}
		return True, {'cookies': [], 'api_user': '123'}

	signin._signin_impl = fake_signin_impl

	success, payload = asyncio.run(signin.signin('client-id', 'state-1', [], 'storage.json'))

	assert success is True
	assert payload == {'cookies': [], 'api_user': '123'}
	assert call_force_fresh_login == [False, True]
