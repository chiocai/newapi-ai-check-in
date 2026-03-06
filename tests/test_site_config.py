import json
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.config import AppConfig


def test_load_sites_and_expand_global_linuxdo_accounts(tmp_path, monkeypatch):
	sites_file = tmp_path / 'sites.txt'
	sites_file.write_text(
		'\n'.join(
			[
				'# comment',
				'std | https://std.example.com | newapi | linuxdo_client_id=client-std',
				'auto | https://auto.example.com | auto-waf',
				'manual | https://manual.example.com | manual:/api/user/checkin',
				'waf | https://waf.example.com | newapi-waf',
				'turn | https://turn.example.com | turnstile:site-key',
			]
		),
		encoding='utf-8',
	)

	monkeypatch.setenv('NEWAPI_SITES_FILE', str(sites_file))
	monkeypatch.delenv('PROVIDERS', raising=False)
	monkeypatch.setenv(
		'ACCOUNTS',
		json.dumps(
			{
				'linux.do': [{'username': 'user1', 'password': 'pass1'}],
				'accounts': [{'provider': 'x666', 'linux.do': {'username': 'user2', 'password': 'pass2'}}],
			}
		),
	)

	app_config = AppConfig.load_from_env()
	account_map = {account.provider: account for account in app_config.accounts}

	assert app_config.get_provider('std').sign_in_path is None
	assert app_config.get_provider('std').linuxdo_client_id == 'client-std'
	assert app_config.get_provider('auto').sign_in_path is None
	assert app_config.get_provider('auto').bypass_method == 'waf_cookies'
	assert app_config.get_provider('manual').sign_in_path == '/api/user/checkin'
	assert app_config.get_provider('waf').bypass_method == 'waf_cookies'
	assert app_config.get_provider('turn').turnstile_site_key == 'site-key'

	assert {'std', 'auto', 'manual', 'waf', 'turn', 'x666'} <= set(account_map)
	assert account_map['std'].checkin is True
	assert account_map['auto'].checkin is False
	assert account_map['manual'].checkin is False
	assert account_map['waf'].checkin is True
	assert account_map['turn'].checkin is True


def test_explicit_site_account_wins_over_auto_generated(tmp_path, monkeypatch):
	sites_file = tmp_path / 'sites.txt'
	sites_file.write_text(
		'std | https://std.example.com | newapi\nother | https://other.example.com | newapi\n',
		encoding='utf-8',
	)

	monkeypatch.setenv('NEWAPI_SITES_FILE', str(sites_file))
	monkeypatch.delenv('PROVIDERS', raising=False)
	monkeypatch.setenv(
		'ACCOUNTS',
		json.dumps(
			{
				'linux.do': [{'username': 'user1', 'password': 'pass1'}],
				'accounts': [{'provider': 'std'}],
			}
		),
	)

	app_config = AppConfig.load_from_env()
	std_accounts = [account for account in app_config.accounts if account.provider == 'std']
	other_accounts = [account for account in app_config.accounts if account.provider == 'other']

	assert len(std_accounts) == 1
	assert len(other_accounts) == 1
	assert std_accounts[0].checkin is True


def test_runtime_overrides_are_applied_over_txt(tmp_path, monkeypatch):
	sites_file = tmp_path / 'sites.txt'
	sites_file.write_text(
		'turn | https://turn.example.com | turnstile\nstd | https://std.example.com | newapi\n',
		encoding='utf-8',
	)
	runtime_file = tmp_path / 'runtime.json'
	runtime_file.write_text(
		json.dumps(
			{
				'sites': {
					'turn': {
						'linuxdo_client_id': 'runtime-linuxdo',
						'turnstile_site_key': 'runtime-site-key',
					},
					'std': {
						'linuxdo_client_id': 'std-client-id',
					},
				}
			}
		),
		encoding='utf-8',
	)

	monkeypatch.setenv('NEWAPI_SITES_FILE', str(sites_file))
	monkeypatch.setenv('NEWAPI_SITES_RUNTIME_FILE', str(runtime_file))
	monkeypatch.delenv('PROVIDERS', raising=False)
	monkeypatch.setenv(
		'ACCOUNTS',
		json.dumps(
			{
				'linux.do': [{'username': 'user1', 'password': 'pass1'}],
				'accounts': [],
			}
		),
	)

	app_config = AppConfig.load_from_env()

	assert app_config.runtime_sites_file == str(runtime_file)
	assert app_config.get_provider('turn').linuxdo_client_id == 'runtime-linuxdo'
	assert app_config.get_provider('turn').turnstile_site_key == 'runtime-site-key'
	assert app_config.get_provider('std').linuxdo_client_id == 'std-client-id'


def test_special_sites_are_not_auto_expanded_from_global_linuxdo(tmp_path, monkeypatch):
	sites_file = tmp_path / 'sites.txt'
	sites_file.write_text(
		'\n'.join(
			[
				'std | https://std.example.com | newapi',
				'x666 | https://x666.example.com | special:x666',
			]
		),
		encoding='utf-8',
	)

	monkeypatch.setenv('NEWAPI_SITES_FILE', str(sites_file))
	monkeypatch.delenv('PROVIDERS', raising=False)
	monkeypatch.setenv(
		'ACCOUNTS',
		json.dumps(
			{
				'linux.do': [{'username': 'user1', 'password': 'pass1'}],
				'accounts': [],
			}
		),
	)

	app_config = AppConfig.load_from_env()
	providers = [account.provider for account in app_config.accounts]

	assert 'std' in providers
	assert 'x666' not in providers


def test_x666_access_token_can_come_from_site_file(tmp_path, monkeypatch):
	sites_file = tmp_path / 'sites.txt'
	sites_file.write_text(
		'x666 | https://x666.example.com | special:x666 | access_token=token-from-site\n',
		encoding='utf-8',
	)

	monkeypatch.setenv('NEWAPI_SITES_FILE', str(sites_file))
	monkeypatch.delenv('PROVIDERS', raising=False)
	monkeypatch.setenv(
		'ACCOUNTS',
		json.dumps(
			{
				'linux.do': [{'username': 'user1', 'password': 'pass1'}],
				'accounts': [],
			}
		),
	)

	app_config = AppConfig.load_from_env()
	x666_accounts = [account for account in app_config.accounts if account.provider == 'x666']

	assert len(x666_accounts) == 1
	assert x666_accounts[0].get('access_token') == 'token-from-site'
	assert x666_accounts[0].linux_do is None
