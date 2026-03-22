import sys
from datetime import datetime
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from main import (
	BEIJING_TZ,
	build_account_runtime_identity,
	build_failure_window_skip_result,
	collect_failure_window_skip_results,
	format_beijing_day_window_label,
	get_beijing_day_window_start_ts,
	get_failure_window_metadata,
	update_failure_window_state_from_results,
)
from utils.config import AccountConfig, AppConfig, ProviderConfig, SiteDefinition
from utils.recent_success_state import load_recent_success_state


def build_app_config(accounts):
	std_provider = ProviderConfig(
		name='std',
		origin='https://std.example.com',
		sign_in_path=None,
		linuxdo_client_id='client-std',
	)
	anyrouter_provider = ProviderConfig(
		name='anyrouter',
		origin='https://anyrouter.top',
		sign_in_path='/api/user/sign_in',
		linuxdo_client_id='client-anyrouter',
		bypass_method='waf_cookies',
	)
	return AppConfig(
		providers={
			'std': std_provider,
			'anyrouter': anyrouter_provider,
		},
		accounts=accounts,
		site_definitions={
			'std': SiteDefinition(name='std', provider=std_provider, checkin=True, mode='newapi'),
			'anyrouter': SiteDefinition(name='anyrouter', provider=anyrouter_provider, checkin=False, mode='manual'),
		},
	)


def test_build_account_runtime_identity_is_stable_for_linuxdo_account():
	account = AccountConfig.from_dict(
		{
			'provider': 'std',
			'linux.do': {'username': 'user-a', 'password': 'pass-a'},
		},
		0,
	)

	assert build_account_runtime_identity(account, 0) == 'std|linux.do|user-a'
	assert build_account_runtime_identity(account, 9) == 'std|linux.do|user-a'


def test_get_failure_window_metadata_reports_active_window():
	now_ts = 1_700_000_000
	window_started_at = get_beijing_day_window_start_ts(now_ts)
	window_state = {
		'window_started_at': window_started_at,
		'failed_identities': ['std|linux.do|user-a'],
		'accounts': {},
	}

	metadata = get_failure_window_metadata(window_state, now_ts)

	assert metadata['window_active'] is True
	assert metadata['current_window_started_at'] == window_started_at
	assert metadata['window_date'] == format_beijing_day_window_label(window_started_at)
	assert metadata['failed_identities'] == {'std|linux.do|user-a'}


def test_build_failure_window_skip_result_restores_balances_from_state():
	account = AccountConfig.from_dict(
		{
			'name': 'std-1',
			'provider': 'std',
			'linux.do': {'username': 'user-a', 'password': 'pass-a'},
		},
		0,
	)
	app_config = build_app_config([account])

	result = build_failure_window_skip_result(
		0,
		account,
		app_config,
		{
			'balances': {
				'linux.do': {'quota': 12.5, 'used': 1.0, 'bonus': 0.0},
			}
		},
	)

	assert result['success'] is True
	assert result['status'] == 'skipped_failure_window'
	assert result['balances'] == {
		'linux.do': {'quota': 12.5, 'used': 1.0, 'bonus': 0.0},
	}


def test_collect_failure_window_skip_results_only_skips_non_failed_known_accounts():
	accounts = [
		AccountConfig.from_dict(
			{
				'name': 'std-1',
				'provider': 'std',
				'linux.do': {'username': 'user-a', 'password': 'pass-a'},
			},
			0,
		),
		AccountConfig.from_dict(
			{
				'name': 'std-2',
				'provider': 'std',
				'linux.do': {'username': 'user-b', 'password': 'pass-b'},
			},
			1,
		),
		AccountConfig.from_dict(
			{
				'name': 'anyrouter-1',
				'provider': 'anyrouter',
				'linux.do': {'username': 'user-c', 'password': 'pass-c'},
			},
			2,
		),
	]
	app_config = build_app_config(accounts)
	now_ts = 1_700_000_000
	window_started_at = get_beijing_day_window_start_ts(now_ts)
	window_state = {
		'window_started_at': window_started_at,
		'failed_identities': ['std|linux.do|user-b'],
		'accounts': {
			'std|linux.do|user-a': {
				'balances': {'linux.do': {'quota': 5.0, 'used': 0.0, 'bonus': 0.0}},
			},
			'std|linux.do|user-b': {
				'balances': {'linux.do': {'quota': 9.0, 'used': 0.0, 'bonus': 0.0}},
			},
		},
	}

	skip_results, metadata = collect_failure_window_skip_results(app_config, window_state, now_ts)

	assert metadata['window_active'] is True
	assert list(skip_results) == [0]
	assert skip_results[0]['status'] == 'skipped_failure_window'
	assert skip_results[0]['balances']['linux.do']['quota'] == 5.0


def test_collect_failure_window_skip_results_keeps_new_accounts_runnable():
	accounts = [
		AccountConfig.from_dict(
			{
				'name': 'std-1',
				'provider': 'std',
				'linux.do': {'username': 'user-a', 'password': 'pass-a'},
			},
			0,
		),
	]
	app_config = build_app_config(accounts)
	now_ts = 1_700_000_000
	window_started_at = get_beijing_day_window_start_ts(now_ts)
	window_state = {
		'window_started_at': window_started_at,
		'failed_identities': [],
		'accounts': {},
	}

	skip_results, metadata = collect_failure_window_skip_results(app_config, window_state, now_ts)

	assert metadata['window_active'] is True
	assert skip_results == {}


def test_collect_failure_window_skip_results_respects_site_level_always_run():
	account = AccountConfig.from_dict(
		{
			'name': 'std-1',
			'provider': 'std',
			'linux.do': {'username': 'user-a', 'password': 'pass-a'},
		},
		0,
	)
	app_config = build_app_config([account])
	std_provider = app_config.get_provider('std')
	app_config.providers['std'] = std_provider.apply_overrides({'failure_window_mode': 'always-run'})
	now_ts = 1_700_000_000
	window_started_at = get_beijing_day_window_start_ts(now_ts)
	window_state = {
		'window_started_at': window_started_at,
		'failed_identities': [],
		'accounts': {
			'std|linux.do|user-a': {
				'balances': {'linux.do': {'quota': 5.0, 'used': 0.0, 'bonus': 0.0}},
			},
		},
	}

	skip_results, metadata = collect_failure_window_skip_results(app_config, window_state, now_ts)

	assert metadata['window_active'] is True
	assert skip_results == {}


def test_collect_failure_window_skip_results_respects_global_site_file_always_run():
	account = AccountConfig.from_dict(
		{
			'name': 'std-1',
			'provider': 'std',
			'linux.do': {'username': 'user-a', 'password': 'pass-a'},
		},
		0,
	)
	app_config = build_app_config([account])
	app_config.site_file_options = {'failure_window_mode': 'always-run'}
	now_ts = 1_700_000_000
	window_started_at = get_beijing_day_window_start_ts(now_ts)
	window_state = {
		'window_started_at': window_started_at,
		'failed_identities': [],
		'accounts': {
			'std|linux.do|user-a': {
				'balances': {'linux.do': {'quota': 5.0, 'used': 0.0, 'bonus': 0.0}},
			},
		},
	}

	skip_results, metadata = collect_failure_window_skip_results(app_config, window_state, now_ts)

	assert metadata['window_active'] is True
	assert skip_results == {}


def test_update_failure_window_state_refreshes_failed_set_and_keeps_skipped_entries():
	account = AccountConfig.from_dict(
		{
			'name': 'std-1',
			'provider': 'std',
			'linux.do': {'username': 'user-a', 'password': 'pass-a'},
		},
		0,
	)
	app_config = build_app_config([account])
	identity = build_account_runtime_identity(account, 0)

	failed_state = update_failure_window_state_from_results(
		{
			'version': 1,
			'window_started_at': 1_700_000_000,
			'failed_identities': [],
			'accounts': {},
		},
		[
			{
				'success': False,
				'status': 'failed',
				'site_origin': 'https://std.example.com',
				'error_summary': 'HTTP 403',
			}
		],
		app_config,
		1_700_000_060,
		1_700_000_000,
	)

	assert failed_state['failed_identities'] == [identity]
	assert failed_state['accounts'][identity]['last_failure_at'] == 1_700_000_060

	recovered_state = update_failure_window_state_from_results(
		failed_state,
		[
			{
				'success': True,
				'status': 'success',
				'site_origin': 'https://std.example.com',
				'balances': {'linux.do': {'quota': 3.5, 'used': 0.0, 'bonus': 0.0}},
				'failure_window_skip_eligible': True,
			}
		],
		app_config,
		1_700_000_120,
		1_700_000_000,
	)

	assert recovered_state['failed_identities'] == []
	assert recovered_state['accounts'][identity]['balances']['linux.do']['quota'] == 3.5

	skipped_state = update_failure_window_state_from_results(
		recovered_state,
		[
			{
				'success': True,
				'status': 'skipped_failure_window',
				'site_origin': 'https://std.example.com',
				'balances': {'linux.do': {'quota': 3.5, 'used': 0.0, 'bonus': 0.0}},
			}
		],
		app_config,
		1_700_000_180,
		1_700_000_000,
	)

	assert skipped_state['accounts'][identity]['balances']['linux.do']['quota'] == 3.5


def test_success_without_skip_eligibility_does_not_enter_failure_window_accounts():
	account = AccountConfig.from_dict(
		{
			'name': 'std-1',
			'provider': 'std',
			'linux.do': {'username': 'user-a', 'password': 'pass-a'},
		},
		0,
	)
	app_config = build_app_config([account])
	identity = build_account_runtime_identity(account, 0)

	state = update_failure_window_state_from_results(
		{
			'version': 1,
			'window_started_at': 1_700_000_000,
			'failed_identities': [],
			'accounts': {},
		},
		[
			{
				'success': True,
				'status': 'success',
				'site_origin': 'https://std.example.com',
				'balances': {'linux.do': {'quota': 3.5, 'used': 0.0, 'bonus': 0.0}},
				'failure_window_skip_eligible': False,
			}
		],
		app_config,
		1_700_000_120,
		1_700_000_000,
	)

	assert identity not in state['accounts']
	assert state['failed_identities'] == []


def test_success_with_skip_eligibility_enters_failure_window_accounts():
	account = AccountConfig.from_dict(
		{
			'name': 'std-1',
			'provider': 'std',
			'linux.do': {'username': 'user-a', 'password': 'pass-a'},
		},
		0,
	)
	app_config = build_app_config([account])
	identity = build_account_runtime_identity(account, 0)

	state = update_failure_window_state_from_results(
		{
			'version': 1,
			'window_started_at': 1_700_000_000,
			'failed_identities': [],
			'accounts': {},
		},
		[
			{
				'success': True,
				'status': 'success',
				'site_origin': 'https://std.example.com',
				'balances': {'linux.do': {'quota': 6.0, 'used': 0.0, 'bonus': 0.0}},
				'success_detail': '+$1.0 | $6.0',
				'failure_window_skip_eligible': True,
			}
		],
		app_config,
		1_700_000_180,
		1_700_000_000,
	)

	assert identity in state['accounts']
	assert state['accounts'][identity]['balances']['linux.do']['quota'] == 6.0


def test_failure_window_expires_to_full_run():
	now_ts = 1_700_000_000
	previous_day_window_started_at = get_beijing_day_window_start_ts(now_ts - (24 * 60 * 60))
	window_state = {
		'window_started_at': previous_day_window_started_at,
		'failed_identities': ['std|linux.do|user-a'],
		'accounts': {
			'std|linux.do|user-a': {
				'balances': {'linux.do': {'quota': 5.0, 'used': 0.0, 'bonus': 0.0}},
			},
		},
	}

	metadata = get_failure_window_metadata(window_state, now_ts)

	assert metadata['window_active'] is False
	assert metadata['current_window_started_at'] == get_beijing_day_window_start_ts(now_ts)


def test_failure_window_resets_after_beijing_midnight_even_within_24_hours():
	first_run_ts = int(datetime(2026, 3, 20, 23, 50, 0, tzinfo=BEIJING_TZ).timestamp())
	second_run_ts = int(datetime(2026, 3, 21, 0, 10, 0, tzinfo=BEIJING_TZ).timestamp())
	window_state = {
		'window_started_at': get_beijing_day_window_start_ts(first_run_ts),
		'failed_identities': ['std|linux.do|user-a'],
		'accounts': {},
	}

	metadata = get_failure_window_metadata(window_state, second_run_ts)

	assert metadata['window_active'] is False
	assert metadata['window_started_at'] != metadata['current_window_started_at']


def test_load_recent_success_state_preserves_failure_window_metadata(tmp_path):
	state_file = tmp_path / 'window-state.json'
	state_file.write_text(
		'{"version":1,"window_started_at":1700000000,"failed_identities":["std|linux.do|user-a"],"accounts":{"std|linux.do|user-a":{"balances":{}}}}',
		encoding='utf-8',
	)

	state = load_recent_success_state(str(state_file))

	assert state['window_started_at'] == 1_700_000_000
	assert state['failed_identities'] == ['std|linux.do|user-a']
	assert 'std|linux.do|user-a' in state['accounts']
