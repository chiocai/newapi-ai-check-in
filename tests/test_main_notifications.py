import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from main import build_site_notification_groups


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
