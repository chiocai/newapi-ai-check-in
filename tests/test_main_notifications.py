import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from main import (
	apply_waf_runtime_overrides_for_failed_accounts,
	build_site_notification_groups,
	collect_failed_account_indices,
	rerun_failed_accounts_once,
	should_enable_waf_retry,
)


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


def test_collect_failed_account_indices():
	account_results = [
		{'success': True},
		{'success': False},
		RuntimeError('boom'),
		{'success': True},
	]

	assert collect_failed_account_indices(account_results) == [1, 2]


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
