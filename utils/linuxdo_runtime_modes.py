#!/usr/bin/env python3
"""
Linux.do 账号维度运行时模式缓存
"""

import json
import os
import threading
import time
from urllib.parse import urlparse

DEFAULT_LINUXDO_RUNTIME_MODES_FILE = 'storage-states/linuxdo_runtime_modes.json'
LINUXDO_RUNTIME_MODES_FILE_ENV = 'LINUXDO_RUNTIME_MODES_FILE'
LINUXDO_RUNTIME_MODE_TTL_SECONDS = max(
    3600,
    int(os.getenv('LINUXDO_RUNTIME_MODE_TTL_SECONDS', '604800')),
)

CALLBACK_MODE_AUTO = 'auto'
CALLBACK_MODE_BROWSER_COMPLETE = 'browser_complete'

CHECKIN_MODE_AUTO = 'auto'
CHECKIN_MODE_BROWSER_FIRST = 'browser_first'

_RUNTIME_MODE_LOCK = threading.RLock()


def _resolve_runtime_modes_file(state_file: str = '') -> str:
    if state_file:
        return state_file
    return os.getenv(LINUXDO_RUNTIME_MODES_FILE_ENV, DEFAULT_LINUXDO_RUNTIME_MODES_FILE)


def _default_runtime_modes_state() -> dict:
    return {
        'version': 1,
        'entries': {},
    }


def _normalize_runtime_modes_state(payload: dict | None) -> dict:
    state = _default_runtime_modes_state()
    if not isinstance(payload, dict):
        return state

    entries = payload.get('entries')
    if not isinstance(entries, dict):
        entries = {}

    state['version'] = payload.get('version', 1)
    state['entries'] = entries
    return state


def _build_runtime_mode_key(provider_origin: str, username_hash: str) -> str:
    provider_host = urlparse(provider_origin).netloc.lower()
    return f'{provider_host}#{username_hash}'


def _normalize_runtime_mode_entry(entry: dict | None) -> dict:
    if not isinstance(entry, dict):
        return {}

    normalized = dict(entry)
    normalized['callback_mode'] = entry.get('callback_mode', CALLBACK_MODE_AUTO)
    normalized['callback_reason'] = entry.get('callback_reason', '')
    normalized['callback_updated_at'] = int(entry.get('callback_updated_at', 0) or 0)
    normalized['checkin_mode'] = entry.get('checkin_mode', CHECKIN_MODE_AUTO)
    normalized['checkin_reason'] = entry.get('checkin_reason', '')
    normalized['checkin_updated_at'] = int(entry.get('checkin_updated_at', 0) or 0)
    return normalized


def _prune_expired_entry(entry: dict) -> tuple[dict, bool]:
    now = int(time.time())
    changed = False
    normalized = _normalize_runtime_mode_entry(entry)

    if (
        normalized.get('callback_mode') == CALLBACK_MODE_BROWSER_COMPLETE
        and now - normalized.get('callback_updated_at', 0) > LINUXDO_RUNTIME_MODE_TTL_SECONDS
    ):
        normalized['callback_mode'] = CALLBACK_MODE_AUTO
        normalized['callback_reason'] = ''
        normalized['callback_updated_at'] = 0
        changed = True

    if (
        normalized.get('checkin_mode') == CHECKIN_MODE_BROWSER_FIRST
        and now - normalized.get('checkin_updated_at', 0) > LINUXDO_RUNTIME_MODE_TTL_SECONDS
    ):
        normalized['checkin_mode'] = CHECKIN_MODE_AUTO
        normalized['checkin_reason'] = ''
        normalized['checkin_updated_at'] = 0
        changed = True

    if (
        normalized.get('callback_mode') == CALLBACK_MODE_AUTO
        and normalized.get('checkin_mode') == CHECKIN_MODE_AUTO
    ):
        return {}, True

    return normalized, changed


def _load_runtime_modes_state_unlocked(state_file: str) -> dict:
    try:
        if os.path.exists(state_file):
            with open(state_file, 'r', encoding='utf-8') as f:
                payload = json.load(f)
                return _normalize_runtime_modes_state(payload)
    except Exception as e:
        print(f'Warning: Failed to load LinuxDo runtime modes: {e}')
    return _default_runtime_modes_state()


def _save_runtime_modes_state_unlocked(state_file: str, state: dict) -> None:
    try:
        state_dir = os.path.dirname(state_file)
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)

        tmp_file = f'{state_file}.tmp'
        with open(tmp_file, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp_file, state_file)
    except Exception as e:
        print(f'Warning: Failed to save LinuxDo runtime modes: {e}')


def _load_and_prune_runtime_modes_state(state_file: str) -> dict:
    with _RUNTIME_MODE_LOCK:
        state = _load_runtime_modes_state_unlocked(state_file)
        entries = state.get('entries', {})
        changed = False
        pruned_entries = {}

        for key, entry in entries.items():
            normalized, entry_changed = _prune_expired_entry(entry)
            if normalized:
                pruned_entries[key] = normalized
            if entry_changed or normalized != entry:
                changed = True

        if changed:
            state['entries'] = pruned_entries
            _save_runtime_modes_state_unlocked(state_file, state)
        else:
            state['entries'] = pruned_entries

        return state


def get_linuxdo_runtime_modes(
    provider_origin: str,
    username_hash: str,
    state_file: str = '',
) -> dict:
    resolved_state_file = _resolve_runtime_modes_file(state_file)
    state = _load_and_prune_runtime_modes_state(resolved_state_file)
    entry = state.get('entries', {}).get(_build_runtime_mode_key(provider_origin, username_hash), {})
    return _normalize_runtime_mode_entry(entry)


def _update_linuxdo_runtime_modes(
    provider_origin: str,
    username_hash: str,
    state_file: str,
    updater,
) -> dict:
    resolved_state_file = _resolve_runtime_modes_file(state_file)
    with _RUNTIME_MODE_LOCK:
        state = _load_runtime_modes_state_unlocked(resolved_state_file)
        entries = state.get('entries', {})
        key = _build_runtime_mode_key(provider_origin, username_hash)
        current_entry, _ = _prune_expired_entry(entries.get(key, {}))
        updated_entry = updater(_normalize_runtime_mode_entry(current_entry))
        if updated_entry:
            entries[key] = updated_entry
        else:
            entries.pop(key, None)
        state['entries'] = entries
        _save_runtime_modes_state_unlocked(resolved_state_file, state)
        return _normalize_runtime_mode_entry(entries.get(key, {}))


def mark_callback_browser_complete(
    provider_origin: str,
    username_hash: str,
    reason: str,
    state_file: str = '',
) -> dict:
    now = int(time.time())

    def updater(entry: dict) -> dict:
        entry['callback_mode'] = CALLBACK_MODE_BROWSER_COMPLETE
        entry['callback_reason'] = reason
        entry['callback_updated_at'] = now
        return entry

    return _update_linuxdo_runtime_modes(provider_origin, username_hash, state_file, updater)


def mark_checkin_browser_first(
    provider_origin: str,
    username_hash: str,
    reason: str,
    state_file: str = '',
) -> dict:
    now = int(time.time())

    def updater(entry: dict) -> dict:
        entry['checkin_mode'] = CHECKIN_MODE_BROWSER_FIRST
        entry['checkin_reason'] = reason
        entry['checkin_updated_at'] = now
        return entry

    return _update_linuxdo_runtime_modes(provider_origin, username_hash, state_file, updater)


def clear_checkin_browser_first(
    provider_origin: str,
    username_hash: str,
    state_file: str = '',
) -> dict:
    def updater(entry: dict) -> dict:
        entry['checkin_mode'] = CHECKIN_MODE_AUTO
        entry['checkin_reason'] = ''
        entry['checkin_updated_at'] = 0
        if entry.get('callback_mode') == CALLBACK_MODE_AUTO:
            return {}
        return entry

    return _update_linuxdo_runtime_modes(provider_origin, username_hash, state_file, updater)
