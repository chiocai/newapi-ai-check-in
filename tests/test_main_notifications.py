import asyncio
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from checkin import should_rebuild_provider_cache, summarize_linuxdo_auth_state_error
from main import (
	apply_waf_runtime_overrides_for_failed_accounts,
	build_site_notification_groups,
	collect_failed_account_indices,
	collect_linuxdo_backoff_retry_indices,
	get_error_label,
	prewarm_linuxdo_sessions,
	rerun_failed_accounts_once,
	should_enable_linuxdo_backoff_retry,
	should_enable_waf_retry,
	should_skip_failed_retry,
)
from utils.config import AccountConfig


def test_build_site_notification_groups_merges_same_site_without_amounts():
	sorted_results = [
		{
			'provider': 'alpha',
			'site_origin': 'https://alpha.example.com',
			'account_name': 'alpha-1',
			'success': True,
			'status': 'success',
			'failed_methods': [],
		},
		{
			'provider': 'alpha',
			'site_origin': 'https://alpha.example.com',
			'account_name': 'alpha-2',
			'success': True,
			'status': 'success',
			'failed_methods': [],
		},
	]

	groups = build_site_notification_groups(sorted_results)

	assert groups == [
		{
			'provider': 'alpha',
			'site_label': 'alpha.example.com',
			'line': '✅ alpha.example.com: 2/2 账号签到成功',
			'success_accounts': 2,
			'total_accounts': 2,
		}
	]
	assert '$' not in groups[0]['line']


def test_build_site_notification_groups_includes_failure_summary():
	sorted_results = [
		{
			'provider': 'beta',
			'site_origin': 'https://beta.example.com',
			'account_name': 'beta-1',
			'success': True,
			'status': 'partial',
			'failed_methods': ['github'],
		},
		{
			'provider': 'beta',
			'site_origin': 'https://beta.example.com',
			'account_name': 'beta-2',
			'success': False,
			'status': 'failed',
			'failed_methods': ['linux.do'],
			'error_summary': '401 Unauthorized',
		},
	]

	groups = build_site_notification_groups(sorted_results)

	assert groups[0]['line'].startswith('⚠️ beta.example.com: 1/2 账号签到成功')
	assert 'beta-1: 部分失败(github)' in groups[0]['line']
	assert 'beta-2: 401 Unauthorized' in groups[0]['line']
	assert '$' not in groups[0]['line']


def test_build_site_notification_groups_shows_success_detail_for_x666_and_anyrouter():
	sorted_results = [
		{
			'provider': 'x666',
			'site_origin': 'https://x666.me',
			'account_name': 'x666-1',
			'success': True,
			'status': 'success',
			'success_detail': '🎰 +$75.0 | $0',
		},
		{
			'provider': 'x666',
			'site_origin': 'https://x666.me',
			'account_name': 'x666-2',
			'success': True,
			'status': 'success',
			'success_detail': '🎰 +$1800.0 | $0',
		},
	]

	groups = build_site_notification_groups(sorted_results)

	assert groups[0]['line'].startswith('✅ x666.me: 2/2 账号签到成功 | ')
	assert 'x666-1: 🎰 +$75.0 | $0' in groups[0]['line']
	assert 'x666-2: 🎰 +$1800.0 | $0' in groups[0]['line']


def test_build_site_notification_groups_prefers_structured_error_summary():
	sorted_results = [
		{
			'provider': 'wong',
			'site_origin': 'https://wzw.pp.ua',
			'account_name': 'wong-2',
			'success': False,
			'status': 'failed',
			'failed_methods': ['linux.do'],
			'error_label': '🔥 高负载',
			'error_summary': 'Linux.do 授权页高负载，请稍后重试',
			'error': 'All 3 attempts failed: Linux.do authorization failed',
		},
	]

	groups = build_site_notification_groups(sorted_results)

	assert 'wong-2: 🔥 高负载' in groups[0]['line']
	assert 'All 3 attempts failed' not in groups[0]['line']


def test_build_site_notification_groups_uses_partial_error_label():
	sorted_results = [
		{
			'provider': 'beta',
			'site_origin': 'https://beta.example.com',
			'account_name': 'beta-1',
			'success': True,
			'status': 'partial',
			'failed_methods': ['linux.do'],
			'error_label': '🧩 hCaptcha',
		},
	]

	groups = build_site_notification_groups(sorted_results)

	assert 'beta-1: 部分失败(linux.do, 🧩 hCaptcha)' in groups[0]['line']


def test_collect_failed_account_indices():
	account_results = [
		{'success': True},
		{'success': False},
		RuntimeError('boom'),
		{'success': True},
	]

	assert collect_failed_account_indices(account_results) == [1, 2]


def test_should_enable_linuxdo_backoff_retry():
	assert should_enable_linuxdo_backoff_retry({
		'success': False,
		'error_type': 'linuxdo_high_load',
		'error_summary': 'Linux.do 授权页高负载，请稍后重试',
	}) is True
	assert should_enable_linuxdo_backoff_retry({
		'success': False,
		'error_type': 'linuxdo_cloudflare_challenge',
		'error_summary': 'Linux.do Cloudflare 挑战页',
	}) is True
	assert should_enable_linuxdo_backoff_retry({
		'success': False,
		'error_type': 'linuxdo_hcaptcha_login',
		'error_summary': 'Linux.do 登录页人机验证(hCaptcha)',
	}) is False


def test_get_error_label():
	assert get_error_label('linuxdo_hcaptcha_login', 'Linux.do 登录页人机验证(hCaptcha)') == '🧩 hCaptcha'
	assert get_error_label('linuxdo_high_load', 'Linux.do 授权页高负载，请稍后重试') == '🔥 高负载'
	assert get_error_label('linuxdo_sso_provider_stuck', 'Linux.do SSO 中转页卡住') == '🔄 SSO 卡住'
	assert get_error_label('linuxdo_auth_state_failed', '站点 auth state 403/疑似 WAF 拦截') == '🚧 auth state 403'


def test_collect_linuxdo_backoff_retry_indices():
	account_results = [
		{'success': False, 'error_type': 'linuxdo_high_load', 'error_summary': 'Linux.do 授权页高负载，请稍后重试'},
		{'success': False, 'error_type': 'linuxdo_hcaptcha_login', 'error_summary': 'Linux.do 登录页人机验证(hCaptcha)'},
		{'success': True},
		{'success': False, 'error_summary': 'Linux.do Cloudflare 挑战页'},
	]

	assert collect_linuxdo_backoff_retry_indices(account_results) == [0, 3]


def test_should_skip_failed_retry():
	assert should_skip_failed_retry({
		'success': False,
		'error_type': 'linuxdo_high_load',
		'error_label': '🔥 高负载',
	}) is True
	assert should_skip_failed_retry({
		'success': False,
		'error_type': 'linuxdo_sso_provider_stuck',
		'error_label': '🔄 SSO 卡住',
	}) is True
	assert should_skip_failed_retry({
		'success': False,
		'error_type': 'linuxdo_hcaptcha_login',
		'error_label': '🧩 hCaptcha',
	}) is False


def test_rerun_failed_accounts_once_replaces_failed_results(monkeypatch):
	async def fake_process_single_account(index, account_config, app_config, semaphore):
		return {'account_index': index, 'success': True, 'status': 'success'}

	monkeypatch.setattr('main.process_single_account', fake_process_single_account)

	class DummyApp:
		accounts = [object(), object(), object()]

	account_results = [
		{'account_index': 0, 'success': True},
		{'account_index': 1, 'success': False},
		RuntimeError('boom'),
	]

	import asyncio
	result = asyncio.run(rerun_failed_accounts_once(account_results, DummyApp(), asyncio.Semaphore(2)))

	assert result[0]['success'] is True
	assert result[1]['success'] is True
	assert result[2]['success'] is True


def test_rerun_failed_accounts_once_skips_linuxdo_high_load(monkeypatch):
	calls = []

	async def fake_process_single_account(index, account_config, app_config, semaphore):
		calls.append(index)
		return {'account_index': index, 'success': True, 'status': 'success'}

	monkeypatch.setattr('main.process_single_account', fake_process_single_account)

	class DummyApp:
		accounts = [object(), object()]
		runtime_sites_file = 'dummy.json'
		site_definitions = {}
		def get_provider(self, name):
			return None

	account_results = [
		{'account_index': 0, 'success': False, 'provider': 'alpha', 'error_type': 'linuxdo_high_load', 'error_label': '🔥 高负载'},
		{'account_index': 1, 'success': False, 'provider': 'beta', 'error_type': 'linuxdo_hcaptcha_login', 'error_label': '🧩 hCaptcha'},
	]

	result = asyncio.run(rerun_failed_accounts_once(account_results, DummyApp(), asyncio.Semaphore(1)))

	assert calls == [1]
	assert result[0]['error_label'] == '🔥 高负载'
	assert result[1]['success'] is True


def test_prewarm_linuxdo_sessions_deduplicates_accounts(monkeypatch):
	class DummySession:
		def __init__(self, is_logged_in):
			self.is_logged_in = is_logged_in

	async def fake_get_session(username, password, proxy=None, auto_login=True):
		calls.append((username, password, proxy, auto_login))
		return DummySession(True)

	monkeypatch.setattr('main.LinuxDoSessionManager.get_session', fake_get_session)
	monkeypatch.setattr('main.LinuxDoSessionManager.get_session_count', lambda: 1)

	calls = []
	accounts = [
		AccountConfig.from_dict({
			'name': 'acc-1',
			'provider': 'alpha',
			'linux.do': {'username': 'user-a', 'password': 'pass-a'},
		}, 0),
		AccountConfig.from_dict({
			'name': 'acc-2',
			'provider': 'beta',
			'linux.do': {'username': 'user-a', 'password': 'pass-a'},
		}, 1),
		AccountConfig.from_dict({
			'name': 'acc-3',
			'provider': 'gamma',
			'linux.do': {'username': 'user-b', 'password': 'pass-b'},
		}, 2),
	]

	result = asyncio.run(prewarm_linuxdo_sessions(accounts, None, reason='test warm-up'))

	assert result == {'attempted': 2, 'successful': 2, 'failed': 0}
	assert calls == [
		('user-a', 'pass-a', None, True),
		('user-b', 'pass-b', None, True),
	]


def test_should_enable_waf_retry_for_403_error():
	class DummyProvider:
		def needs_waf_cookies(self):
			return False

	class DummySite:
		mode = 'newapi'

	class DummyApp:
		def get_provider(self, name):
			return DummyProvider()
		site_definitions = {'alpha': DummySite()}

	result = {'provider': 'alpha', 'error_summary': 'Failed to get user info: HTTP 403'}
	assert should_enable_waf_retry(result, DummyApp()) is True


def test_should_enable_waf_retry_for_linuxdo_session_expired():
	class DummyProvider:
		def needs_waf_cookies(self):
			return False

	class DummySite:
		mode = 'newapi'

	class DummyApp:
		def get_provider(self, name):
			return DummyProvider()
		site_definitions = {'alpha': DummySite()}

	result = {'provider': 'alpha', 'error_type': 'linuxdo_redirect_login', 'error_label': '🔑 会话失效'}
	assert should_enable_waf_retry(result, DummyApp()) is True


def test_should_enable_waf_retry_for_linuxdo_sso_stuck():
	class DummyProvider:
		def needs_waf_cookies(self):
			return False

	class DummySite:
		mode = 'newapi'

	class DummyApp:
		def get_provider(self, name):
			return DummyProvider()
		site_definitions = {'alpha': DummySite()}

	result = {'provider': 'alpha', 'error_type': 'linuxdo_sso_provider_stuck', 'error_label': '🔄 SSO 卡住'}
	assert should_enable_waf_retry(result, DummyApp()) is True


def test_apply_waf_runtime_overrides_for_failed_accounts(monkeypatch, tmp_path):
	class DummyProvider:
		def __init__(self):
			self.bypass_method = None
		def needs_waf_cookies(self):
			return False
		def apply_overrides(self, overrides):
			new_provider = DummyProvider()
			new_provider.bypass_method = overrides.get('bypass_method')
			return new_provider

	class DummySite:
		mode = 'newapi'

	class DummyApp:
		def __init__(self):
			self.provider = DummyProvider()
			self.site_definitions = {'alpha': DummySite()}
			self.runtime_sites_file = str(tmp_path / 'runtime.json')
		def get_provider(self, name):
			return self.provider if name == 'alpha' else None
		def update_provider(self, name, provider):
			self.provider = provider

	app = DummyApp()
	account_results = [{'provider': 'alpha', 'success': False, 'error_summary': 'HTTP 403'}]

	updated = apply_waf_runtime_overrides_for_failed_accounts(account_results, app)

	assert updated == ['alpha']
	assert app.provider.bypass_method == 'waf_cookies'


def test_should_rebuild_provider_cache_for_anyrouter_html_like_error():
	assert should_rebuild_provider_cache('anyrouter', 'Failed to get user info: Invalid response type') is True
	assert should_rebuild_provider_cache('anyrouter', 'Failed to get user info: HTTP 403') is True
	assert should_rebuild_provider_cache('aipm', 'other random error') is False


def test_summarize_linuxdo_auth_state_error():
	assert summarize_linuxdo_auth_state_error('Failed to get auth state: HTTP 403') == '站点 auth state 403/疑似 WAF 拦截'
	assert summarize_linuxdo_auth_state_error('Failed to get auth state: Invalid response type') == '站点 auth state 返回 HTML'
