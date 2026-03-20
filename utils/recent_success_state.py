#!/usr/bin/env python3
"""
最近成功签到状态管理
"""

import json
import os


def load_recent_success_state(state_file: str) -> dict:
    """加载最近成功状态文件"""
    try:
        if os.path.exists(state_file):
            with open(state_file, 'r', encoding='utf-8') as f:
                payload = json.load(f)
                if isinstance(payload, dict):
                    accounts = payload.get('accounts')
                    if isinstance(accounts, dict):
                        normalized = dict(payload)
                        normalized['version'] = payload.get('version', 1)
                        normalized['accounts'] = accounts
                        return normalized
    except Exception as e:
        print(f'Warning: Failed to load recent success state: {e}')

    return {'version': 1, 'accounts': {}}


def save_recent_success_state(state_file: str, state: dict) -> None:
    """保存最近成功状态文件"""
    try:
        state_dir = os.path.dirname(state_file)
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)

        with open(state_file, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f'Warning: Failed to save recent success state: {e}')
