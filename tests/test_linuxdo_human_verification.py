import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.browser_utils import (
	classify_linuxdo_human_verification_snapshot,
	detect_linuxdo_page_guard_from_text,
)


def test_classify_linuxdo_human_verification_snapshot_blocking():
	snapshot = {
		'has_hcaptcha_modal': True,
		'has_hcaptcha_field': True,
		'human_verification_title': 'Human Verification',
		'verify_button_present': True,
		'verify_button_disabled': True,
		'iframe_count': 1,
		'iframe_response': '',
		'hcaptcha_response': '',
		'grecaptcha_response': '',
		'sitekey': 'a776b4ac-8c4c-441e-986a-c6ee9ed8cf08',
	}

	result = classify_linuxdo_human_verification_snapshot(snapshot)

	assert result == {
		'present': True,
		'solved': False,
		'blocking': True,
		'sitekey': 'a776b4ac-8c4c-441e-986a-c6ee9ed8cf08',
		'verify_button_disabled': True,
		'verify_button_present': True,
		'iframe_count': 1,
		'token_present': False,
	}


def test_classify_linuxdo_human_verification_snapshot_solved():
	snapshot = {
		'has_hcaptcha_modal': True,
		'has_hcaptcha_field': True,
		'human_verification_title': 'Human Verification',
		'verify_button_present': True,
		'verify_button_disabled': False,
		'iframe_count': 1,
		'iframe_response': 'token-123',
		'hcaptcha_response': '',
		'grecaptcha_response': '',
		'sitekey': 'site-key',
	}

	result = classify_linuxdo_human_verification_snapshot(snapshot)

	assert result['present'] is True
	assert result['solved'] is True
	assert result['blocking'] is False
	assert result['token_present'] is True


def test_detect_linuxdo_page_guard_from_text():
	text = """
	Human Verification
	hcaptcha
	Verify
	Just a moment...
	/cdn-cgi/challenge-platform/
	"""

	result = detect_linuxdo_page_guard_from_text(text)

	assert result['human_verification'] is True
	assert result['cloudflare_challenge'] is True
	assert result['human_verification_sitekey'] is None


def test_detect_linuxdo_page_guard_from_text_high_load():
	text = """
	Server is currently experiencing high load.
	Please try again later.
	"""

	result = detect_linuxdo_page_guard_from_text(text)

	assert result['high_load'] is True
