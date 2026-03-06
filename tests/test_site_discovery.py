import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.browser_utils import detect_linuxdo_page_guard_from_text
from utils.site_discovery import (
	extract_runtime_overrides_from_status_payload,
	extract_runtime_overrides_from_text,
	load_runtime_sites_payload,
	update_runtime_site_override,
)


def test_extract_runtime_overrides_from_status_payload():
	payload = {
		'success': True,
		'data': {
			'linuxdo_client_id': 'linuxdo-123',
			'github_client_id': 'github-456',
			'turnstile_site_key': 'turnstile-789',
		},
	}

	assert extract_runtime_overrides_from_status_payload(payload) == {
		'linuxdo_client_id': 'linuxdo-123',
		'github_client_id': 'github-456',
		'turnstile_site_key': 'turnstile-789',
	}


def test_extract_runtime_overrides_from_text():
	html = """
	<a href="https://connect.linux.do/oauth2/authorize?response_type=code&client_id=linuxdo-abc&state=xyz">LinuxDo</a>
	<a href="https://github.com/login/oauth/authorize?client_id=github-def">GitHub</a>
	<div class="cf-turnstile" data-sitekey="turnstile-key"></div>
	"""

	assert extract_runtime_overrides_from_text(html) == {
		'linuxdo_client_id': 'linuxdo-abc',
		'github_client_id': 'github-def',
		'turnstile_site_key': 'turnstile-key',
	}


def test_update_runtime_site_override(tmp_path):
	runtime_file = tmp_path / 'runtime.json'
	update_runtime_site_override(runtime_file, 'demo', {'linuxdo_client_id': 'linuxdo-1'})
	update_runtime_site_override(runtime_file, 'demo', {'turnstile_site_key': 'turnstile-1'})

	payload = load_runtime_sites_payload(runtime_file)

	assert payload['sites']['demo']['linuxdo_client_id'] == 'linuxdo-1'
	assert payload['sites']['demo']['turnstile_site_key'] == 'turnstile-1'
	assert '_updated_at' in payload['sites']['demo']


def test_detect_linuxdo_page_guard_from_text_hcaptcha():
	text = 'Welcome back Human Verification Verify hcaptcha'
	result = detect_linuxdo_page_guard_from_text(text)

	assert result['human_verification'] is True
	assert result['cloudflare_challenge'] is False


def test_detect_linuxdo_page_guard_from_text_cloudflare():
	text = 'Just a moment... checking your browser before accessing /cdn-cgi/challenge-platform/'
	result = detect_linuxdo_page_guard_from_text(text)

	assert result['human_verification'] is False
	assert result['cloudflare_challenge'] is True
