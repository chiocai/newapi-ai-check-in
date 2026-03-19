#!/usr/bin/env python3
"""
调试开关工具
"""

import os


def linuxdo_auth_debug_enabled() -> bool:
	"""是否启用 LinuxDo 授权链路详细调试日志"""
	return os.getenv('LINUXDO_AUTH_DEBUG', '').strip().lower() in {'1', 'true', 'yes', 'on'}
