#!/usr/bin/env python3
"""
自动签到脚本
"""

import asyncio
import copy
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from fnmatch import fnmatch
from itertools import groupby
from urllib.parse import urlparse

from dotenv import load_dotenv

from bootstrap_storage_states import bootstrap_storage_states_from_accounts_env
from checkin import CheckIn
from utils.balance_hash import load_balance_hash, save_balance_hash
from utils.config import AppConfig
from utils.linuxdo_session import LinuxDoSessionManager
from utils.notify import notify
from utils.recent_success_state import load_recent_success_state, save_recent_success_state
from utils.site_discovery import ensure_runtime_site_overrides, update_runtime_site_override

load_dotenv(override=True)
deleted_from_accounts, restored_from_accounts, skipped_from_accounts = bootstrap_storage_states_from_accounts_env(
    overwrite=True,
    purge_existing=True,
)
if deleted_from_accounts:
    print(f"🧹 Deleted {len(deleted_from_accounts)} existing LinuxDo prewarmed file(s) before restore")
if restored_from_accounts:
    print(f"✅ Restored {len(restored_from_accounts)} prewarmed storage state file(s) from ACCOUNTS")
elif skipped_from_accounts:
    print(f"ℹ️ Prewarmed storage states already exist locally, skipped {len(skipped_from_accounts)} file(s)")

BALANCE_HASH_FILE = "balance_hash.txt"
RECENT_SUCCESS_STATE_FILE = os.getenv("RECENT_SUCCESS_STATE_FILE", "storage-states/checkin-success-state.json")
RECENT_SUCCESS_SKIP_TTL_SECONDS = max(0, int(os.getenv("RECENT_SUCCESS_SKIP_HOURS", "24"))) * 60 * 60
RECENT_SUCCESS_SKIP_EXCLUDED_PROVIDERS = {"anyrouter", "x666"}

# 并行处理配置
MAX_CONCURRENT_ACCOUNTS = max(1, int(os.getenv("MAX_CONCURRENT_ACCOUNTS", "10")))  # 最大并发账号数
MAX_CONCURRENT_RUNTIME_DISCOVERY = max(1, int(os.getenv("MAX_CONCURRENT_RUNTIME_DISCOVERY", "10")))  # 运行时自动发现最大并发数
MAX_CONCURRENT_LINUXDO_PRELOGIN = max(1, int(os.getenv("MAX_CONCURRENT_LINUXDO_PRELOGIN", "2")))  # LinuxDo 预登录最大并发数
MAX_FAILED_RETRY_ROUNDS = max(0, int(os.getenv("MAX_FAILED_RETRY_ROUNDS", "1")))  # 主流程完成后的普通失败补跑轮次
MAX_DEFERRED_RETRY_ROUNDS = max(0, int(os.getenv("MAX_DEFERRED_RETRY_ROUNDS", "1")))  # 慢错误延后补跑轮次
MAX_CONCURRENT_DEFERRED_RETRY = max(1, int(os.getenv("MAX_CONCURRENT_DEFERRED_RETRY", "1")))  # 慢错误补跑并发
DEFERRED_RETRY_DELAY_SECONDS = max(0, int(os.getenv("DEFERRED_RETRY_DELAY_SECONDS", "0")))  # 慢错误补跑前等待秒数
LINUXDO_BACKOFF_RETRY_DELAYS = tuple(
    int(item.strip())
    for item in os.getenv("LINUXDO_BACKOFF_RETRY_DELAYS", "60,180").split(",")
    if item.strip()
) or (60, 180)  # Linux.do 高负载/Cloudflare 退避重试延迟（秒）
LINUXDO_PREWARM_ALERT_ERROR_TYPES = {
    "linuxdo_prewarmed_state_missing",
    "linuxdo_prewarmed_state_invalid",
    "linuxdo_redirect_login",
}
DEFERRED_RETRY_ERROR_TYPES = {
    "linuxdo_cloudflare_challenge",
    "linuxdo_auth_state_failed",
    "linuxdo_signin_failed",
    "linuxdo_authorization_failed",
    "linuxdo_allow_button_not_found",
    "linuxdo_oauth_no_code",
    "linuxdo_sso_provider_stuck",
    "linuxdo_redirect_login",
    "linuxdo_page_navigation_error",
    "linuxdo_authorization_navigation_failed",
}


def generate_balance_hash(balances: dict) -> str:
    """生成余额数据的hash"""
    # 将包含 quota 和 used 的结构转换为 {account_name: [quota]} 格式用于 hash 计算
    simple_balances = {}
    if balances:
        for account_key, account_balances in balances.items():
            quota_list = []
            for _, balance_info in account_balances.items():
                quota_list.append(balance_info["quota"])
            simple_balances[account_key] = quota_list

    balance_json = json.dumps(simple_balances, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(balance_json.encode("utf-8")).hexdigest()[:16]


def build_account_runtime_identity(account_config, account_index: int) -> str:
    """构造跨运行稳定的账号标识"""
    provider_name = account_config.provider or "unknown"

    if account_config.linux_do:
        username = account_config.linux_do.get("username", "")
        if username:
            return f"{provider_name}|linux.do|{username}"

    if account_config.github:
        username = account_config.github.get("username", "")
        if username:
            return f"{provider_name}|github|{username}"

    if account_config.cookies:
        api_user = str(account_config.api_user or "")
        if api_user:
            return f"{provider_name}|cookies|{api_user}"

    access_token = account_config.get("access_token")
    if access_token:
        token_hash = hashlib.sha256(str(access_token).encode("utf-8")).hexdigest()[:12]
        return f"{provider_name}|access_token|{token_hash}"

    return f"{provider_name}|name|{account_config.get_display_name(account_index)}"


def should_skip_recent_success(provider_name: str, recent_success_state: dict, identity: str, now_ts: int) -> bool:
    """判断账号是否应因最近成功而跳过"""
    if RECENT_SUCCESS_SKIP_TTL_SECONDS <= 0:
        return False
    if provider_name in RECENT_SUCCESS_SKIP_EXCLUDED_PROVIDERS:
        return False

    accounts_state = recent_success_state.get("accounts", {}) if isinstance(recent_success_state, dict) else {}
    state_entry = accounts_state.get(identity)
    if not isinstance(state_entry, dict):
        return False

    last_success_at = int(state_entry.get("last_success_at", 0) or 0)
    if last_success_at <= 0:
        return False

    return now_ts - last_success_at < RECENT_SUCCESS_SKIP_TTL_SECONDS


def should_track_recent_success(account_config, app_config: AppConfig) -> bool:
    """判断账号是否应参与最近成功跳过逻辑"""
    provider_name = account_config.provider
    if provider_name in RECENT_SUCCESS_SKIP_EXCLUDED_PROVIDERS:
        return False

    site_definition = app_config.site_definitions.get(provider_name)
    if not site_definition:
        return False

    return site_definition.mode not in {"special", "signed"}


def build_recent_success_skip_result(
    account_index: int,
    account_config,
    app_config: AppConfig,
    state_entry: dict,
) -> dict:
    """为 24 小时内已成功的账号构造跳过结果"""
    account_key = f"account_{account_index + 1}"
    account_name = account_config.get_display_name(account_index)
    provider_name = account_config.provider
    provider_config = app_config.get_provider(provider_name)
    balances = state_entry.get("balances", {})
    if not isinstance(balances, dict):
        balances = {}

    return {
        "account_key": account_key,
        "account_name": account_name,
        "account_index": account_index,
        "provider": provider_name,
        "site_origin": provider_config.origin if provider_config else "",
        "success": True,
        "status": "skipped_recent_success",
        "results": [],
        "balances": copy.deepcopy(balances),
        "notification": f"⏭️ {account_name}: 24 小时内已成功，跳过本轮",
        "need_notify": False,
        "successful_methods": [],
        "failed_methods": [],
        "error_summary": None,
        "success_detail": "24 小时内已成功，跳过本轮",
        "error_type": None,
        "error_label": None,
        "error_detail": None,
        "error": None,
    }


def collect_recent_success_skip_results(app_config: AppConfig, recent_success_state: dict, now_ts: int) -> dict[int, dict]:
    """收集应跳过的最近成功账号结果"""
    skip_results = {}
    accounts_state = recent_success_state.get("accounts", {}) if isinstance(recent_success_state, dict) else {}

    for index, account_config in enumerate(app_config.accounts):
        if not should_track_recent_success(account_config, app_config):
            continue

        identity = build_account_runtime_identity(account_config, index)
        if not should_skip_recent_success(account_config.provider, recent_success_state, identity, now_ts):
            continue

        state_entry = accounts_state.get(identity, {})
        skip_results[index] = build_recent_success_skip_result(index, account_config, app_config, state_entry)

    return skip_results


def update_recent_success_state_from_results(
    recent_success_state: dict,
    account_results: list,
    app_config: AppConfig,
    now_ts: int,
) -> dict:
    """根据本轮结果刷新最近成功状态"""
    existing_accounts = recent_success_state.get("accounts", {}) if isinstance(recent_success_state, dict) else {}
    next_accounts = {}

    for index, account_config in enumerate(app_config.accounts):
        if not should_track_recent_success(account_config, app_config):
            continue

        identity = build_account_runtime_identity(account_config, index)
        existing_entry = existing_accounts.get(identity)
        result = account_results[index] if index < len(account_results) else None

        if isinstance(result, dict) and result.get("success") and result.get("status") != "skipped_recent_success":
            next_accounts[identity] = {
                "provider": account_config.provider,
                "account_name": account_config.get_display_name(index),
                "site_origin": result.get("site_origin", ""),
                "last_success_at": now_ts,
                "balances": copy.deepcopy(result.get("balances", {})),
                "success_detail": result.get("success_detail"),
            }
            continue

        if isinstance(result, dict) and not result.get("success"):
            continue

        if isinstance(result, dict) and result.get("status") == "skipped_recent_success" and isinstance(existing_entry, dict):
            carried_entry = copy.deepcopy(existing_entry)
            carried_entry["provider"] = account_config.provider
            carried_entry["account_name"] = account_config.get_display_name(index)
            if result.get("site_origin"):
                carried_entry["site_origin"] = result.get("site_origin")
            if result.get("balances"):
                carried_entry["balances"] = copy.deepcopy(result.get("balances", {}))
            next_accounts[identity] = carried_entry
            continue

        if not isinstance(existing_entry, dict):
            continue

        last_success_at = int(existing_entry.get("last_success_at", 0) or 0)
        if last_success_at <= 0:
            continue
        if now_ts - last_success_at >= RECENT_SUCCESS_SKIP_TTL_SECONDS:
            continue

        next_accounts[identity] = copy.deepcopy(existing_entry)

    return {
        "version": 1,
        "accounts": next_accounts,
    }


def get_error_label(
    error_type: str | None = None,
    error_summary: str | None = None,
    error_detail: str | None = None,
    error: str | None = None,
) -> str | None:
    """将结构化错误映射为更短的通知标签"""
    normalized_summary = (error_summary or '').lower()
    normalized_detail = (error_detail or error or '').lower()

    linuxdo_error_labels = {
        'linuxdo_hcaptcha_login': '🧩 hCaptcha',
        'linuxdo_hcaptcha_authorize': '🧩 hCaptcha',
        'linuxdo_cloudflare_challenge': '☁️ Cloudflare',
        'linuxdo_high_load': '🔥 高负载',
        'linuxdo_sso_provider_stuck': '🔄 SSO 卡住',
        'linuxdo_redirect_login': '🔑 会话失效',
        'linuxdo_prewarmed_state_missing': '🗂️ 缺少预热态',
        'linuxdo_prewarmed_state_invalid': '♻️ 预热态失效',
        'linuxdo_circuit_open': '⛔ OAuth 熔断',
        'linuxdo_client_id_failed': '🆔 client_id',
        'linuxdo_allow_button_not_found': '🚫 未找到允许按钮',
        'linuxdo_authorization_navigation_failed': '🧭 授权页打开失败',
        'linuxdo_authorization_failed': '🚪 授权失败',
        'linuxdo_page_navigation_error': '🧭 页面异常',
        'linuxdo_signin_error': '⚠️ 登录异常',
        'linuxdo_signin_failed': '❌ 登录失败',
        'linuxdo_oauth_no_code': '🧾 OAuth 无 code',
    }
    if error_type in linuxdo_error_labels:
        return linuxdo_error_labels[error_type]

    if error_type == 'linuxdo_auth_state_failed':
        if '403' in normalized_summary or '403' in normalized_detail:
            return '🚧 auth state 403'
        if 'html' in normalized_summary or 'html' in normalized_detail:
            return '📄 auth state HTML'
        if 'cloudflare' in normalized_summary or 'cloudflare' in normalized_detail:
            return '☁️ auth state CF'
        if 'timeout' in normalized_summary or 'timeout' in normalized_detail:
            return '⏱️ auth state 超时'
        return '⚠️ auth state 失败'

    fallback_text = ' '.join(value for value in [error_summary, error_detail, error] if value).lower()
    if 'human verification' in fallback_text or 'hcaptcha' in fallback_text or 'h-captcha' in fallback_text:
        return '🧩 hCaptcha'
    if 'sso provider page is stuck' in fallback_text or 'sso 中转页卡住' in fallback_text or 'sso_provider' in fallback_text:
        return '🔄 SSO 卡住'
    if 'redirected back to login page' in fallback_text or '会话失效' in fallback_text:
        return '🔑 会话失效'
    if 'cloudflare' in fallback_text or 'challenge' in fallback_text:
        return '☁️ Cloudflare'
    if 'turnstile' in fallback_text:
        return '☁️ Cloudflare'
    if 'high load' in fallback_text or '请稍后重试' in fallback_text:
        return '🔥 高负载'
    if 'auth state' in fallback_text and '403' in fallback_text:
        return '🚧 auth state 403'
    if 'auth state' in fallback_text and 'html' in fallback_text:
        return '📄 auth state HTML'

    return error_summary or error_detail or error


def mask_linuxdo_username(username: str) -> str:
    """对 Linux.do 用户名做简单脱敏"""
    if not username:
        return "unknown"
    if len(username) <= 2:
        return f"{username[0]}***"
    if len(username) <= 6:
        return f"{username[:1]}***{username[-1:]}"
    return f"{username[:3]}***{username[-2:]}"


def extract_account_slot_label(account_name: str | None) -> str | None:
    """从账号名提取类似 -1 / -2 的批次标识"""
    if not account_name:
        return None

    match = re.search(r"-(\d+)$", account_name)
    if not match:
        return None
    return f"-{match.group(1)}"


def build_linuxdo_binding_label(account_name: str, account_config) -> str | None:
    """构建日志里展示的 Linux.do 账号标识"""
    if not account_config.linux_do:
        return None

    username = account_config.linux_do.get("username", "")
    if not username:
        return None

    slot_label = extract_account_slot_label(account_name)
    if slot_label:
        return f"{username} ({slot_label})"
    return username


def build_linuxdo_prewarm_alert_lines(prewarm_summary: dict | None, account_results: list[dict]) -> list[str]:
    """汇总 LinuxDo 预热态失效提醒，追加到最终通知中"""
    alert_items = []
    seen = set()

    for issue in (prewarm_summary or {}).get("issues", []):
        issue_type = issue.get("error_type") or ""
        if issue_type not in LINUXDO_PREWARM_ALERT_ERROR_TYPES:
            continue
        username_hash = issue.get("username_hash", "")
        issue_key = ("prewarm", username_hash, issue_type)
        if issue_key in seen:
            continue
        seen.add(issue_key)
        label = get_error_label(issue_type, issue.get("error_summary"), issue.get("error_detail"), issue.get("error"))
        account_label = issue.get("username_mask") or username_hash or "unknown"
        alert_items.append(f"{account_label}: {label or issue.get('error_summary', '预热态异常')}")

    for result in account_results:
        if not isinstance(result, dict):
            continue
        issue_type = result.get("error_type") or ""
        if issue_type not in LINUXDO_PREWARM_ALERT_ERROR_TYPES:
            continue
        issue_key = ("result", result.get("account_name", ""), issue_type)
        if issue_key in seen:
            continue
        seen.add(issue_key)
        label = result.get("error_label") or get_error_label(
            issue_type,
            result.get("error_summary"),
            result.get("error_detail"),
            result.get("error"),
        )
        alert_items.append(f"{result.get('account_name', 'unknown')}: {label or issue_type}")

    if not alert_items:
        return []

    summary = "；".join(alert_items[:3])
    if len(alert_items) > 3:
        summary += f"；其余 {len(alert_items) - 3} 个账号请重新预热"
    return [f"⚠️ LinuxDo 预热态提醒: {summary}；可执行 `uv run python prepare_linuxdo_session.py` 重新预热"]


async def process_single_account(
    account_index: int,
    account_config,
    app_config,
    semaphore: asyncio.Semaphore,
) -> dict:
    """处理单个账号的签到（带并发控制）

    Args:
        account_index: 账号索引
        account_config: 账号配置
        app_config: 应用配置
        semaphore: 并发控制信号量

    Returns:
        包含处理结果的字典
    """
    async with semaphore:
        account_key = f"account_{account_index + 1}"
        account_name = account_config.get_display_name(account_index)

        result = {
            "account_key": account_key,
            "account_name": account_name,
            "account_index": account_index,
            "provider": "",
            "site_origin": "",
            "success": False,
            "status": "failed",
            "results": [],
            "balances": {},
            "notification": "",
            "need_notify": False,
            "successful_methods": [],
            "failed_methods": [],
            "error_summary": None,
            "success_detail": None,
            "error_type": None,
            "error_label": None,
            "error_detail": None,
            "error": None,
        }

        try:
            result["provider"] = account_config.provider
            provider_config = app_config.get_provider(account_config.provider)
            if not provider_config:
                print(f"❌ {account_name}: Provider '{account_config.provider}' configuration not found")
                result["need_notify"] = True
                result["notification"] = f"[FAIL] {account_name}: Provider '{account_config.provider}' configuration not found"
                result["error_summary"] = f"Provider '{account_config.provider}' configuration not found"
                result["error"] = f"Provider '{account_config.provider}' not found"
                return result
            result["site_origin"] = provider_config.origin

            print(f"🌀 Processing {account_name} using provider '{account_config.provider}'\n")
            linuxdo_binding = build_linuxdo_binding_label(account_name, account_config)
            if linuxdo_binding:
                print(f"🔐 {account_name}: Bound Linux.do account -> {linuxdo_binding}")

            # 获取共享的 Linux.do 会话（如果有）
            linuxdo_session = None
            if account_config.linux_do:
                username = account_config.linux_do.get("username")
                if username:
                    linuxdo_session = LinuxDoSessionManager.get_cached_session(username)

            checkin = CheckIn(
                account_name,
                account_config,
                provider_config,
                global_proxy=app_config.global_proxy,
                linuxdo_session=linuxdo_session,
            )
            results = await checkin.execute()
            result["results"] = results

            # 处理多个认证方式的结果
            account_success = False
            successful_methods = []
            failed_methods = []
            failed_details = []
            failed_error_type = None
            failed_error_label = None
            failed_error_detail = None
            this_account_balances = {}

            # 构建单行结果
            line_parts = []
            for auth_method, success, user_info in results:
                if success and user_info and user_info.get("success"):
                    account_success = True
                    successful_methods.append(auth_method)
                    if "quota" in user_info:
                        current_quota = user_info["quota"]
                        current_used = user_info["used_quota"]
                        current_bonus = user_info["bonus_quota"]
                        checkin_reward = user_info.get("checkin_reward")
                        this_account_balances[f"{auth_method}"] = {
                            "quota": current_quota,
                            "used": current_used,
                            "bonus": current_bonus,
                        }
                        if checkin_reward is not None:
                            line_parts.append(f"+${checkin_reward} | ${current_quota}")
                        else:
                            line_parts.append(f"${current_quota}")
                    elif "cdk_results" in user_info:
                        cdk_results = user_info['cdk_results']
                        cdk_parts = []
                        for cdk_result in cdk_results:
                            if isinstance(cdk_result, dict):
                                result_type = cdk_result.get("type", "")
                                if result_type == "checkin_success":
                                    quota = cdk_result.get("quota", 0)
                                    balance = cdk_result.get("balance", 0)
                                    if balance > 0:
                                        cdk_parts.append(f"🎰 +${quota} | ${balance}")
                                    else:
                                        cdk_parts.append(f"🎰 +${quota}")
                                elif result_type == "wheel_success":
                                    total_quota = cdk_result.get("total_quota", 0)
                                    spin_count = cdk_result.get("spin_count", 0)
                                    already_done = cdk_result.get("already_done", False)
                                    if already_done:
                                        cdk_parts.append(f"🎰 已抽x{spin_count} +${total_quota}")
                                    else:
                                        cdk_parts.append(f"🎰 转盘x{spin_count} +${total_quota}")
                                elif result_type == "cdk_list":
                                    total_quota = cdk_result.get("total_quota", 0)
                                    spin_count = cdk_result.get("spin_count", 0)
                                    cdk_parts.append(f"🎰 转盘x{spin_count} +${total_quota}")
                        if cdk_parts:
                            line_parts.append(", ".join(cdk_parts))
                        else:
                            line_parts.append("签到成功")
                    elif "message" in user_info:
                        line_parts.append(user_info['message'])
                    else:
                        line_parts.append("签到成功")
                else:
                    failed_methods.append(auth_method)
                    error_msg = (
                        user_info.get("error_summary")
                        or user_info.get("error", "未知错误")
                    ) if user_info else "未知错误"
                    if failed_error_type is None and user_info:
                        failed_error_type = user_info.get("error_type")
                    if failed_error_label is None and user_info:
                        failed_error_label = get_error_label(
                            user_info.get("error_type"),
                            user_info.get("error_summary"),
                            user_info.get("error_detail"),
                            user_info.get("error"),
                        )
                    if failed_error_detail is None and user_info:
                        failed_error_detail = user_info.get("error_detail") or user_info.get("error")
                    failed_details.append(str(failed_error_label or error_msg)[:80])
                    line_parts.append(str(failed_error_label or error_msg)[:80])

            # 生成单行通知
            if account_success:
                detail = line_parts[0] if line_parts else "签到成功"
                account_result = f"✅ {account_name}: {detail}"
            else:
                detail = line_parts[0] if line_parts else "未知错误"
                account_result = f"❌ {account_name}: {detail}"

            result["success"] = account_success
            result["balances"] = this_account_balances
            result["notification"] = account_result
            result["successful_methods"] = successful_methods
            result["failed_methods"] = failed_methods
            result["error_summary"] = failed_details[0] if failed_details else None
            result["success_detail"] = line_parts[0] if account_success and line_parts else None
            result["error_type"] = failed_error_type
            result["error_label"] = failed_error_label
            result["error_detail"] = failed_error_detail
            if account_success and failed_methods:
                result["status"] = "partial"
            elif account_success:
                result["status"] = "success"
            else:
                result["status"] = "failed"
                result["error"] = result["error_detail"] or result["error_summary"] or result["error"]

            # 如果所有认证方式都失败，需要通知
            if not account_success and results:
                result["need_notify"] = True
                print(f"🔔 {account_name} all authentication methods failed, will send notification")

            # 如果有失败的认证方式，也通知
            if failed_methods and successful_methods:
                result["need_notify"] = True
                print(f"🔔 {account_name} has some failed authentication methods, will send notification")

        except Exception as e:
            print(f"❌ {account_name} processing exception: {e}")
            result["need_notify"] = True
            result["notification"] = f"❌ {account_name}: {str(e)[:80]}"
            result["error_summary"] = str(e)[:80]
            result["error"] = str(e)

        return result


def collect_failed_account_indices(account_results: list) -> list[int]:
    """收集需要补跑的账号索引"""
    failed_indices = []
    for index, result in enumerate(account_results):
        if isinstance(result, Exception):
            failed_indices.append(index)
            continue
        if isinstance(result, dict) and not result.get("success"):
            failed_indices.append(index)
    return failed_indices


def collect_failed_account_indices_for_candidates(account_results: list, candidate_indices: list[int]) -> list[int]:
    """仅针对指定账号索引收集失败账号"""
    failed_indices = []
    for index in candidate_indices:
        if not (0 <= index < len(account_results)):
            continue
        result = account_results[index]
        if isinstance(result, Exception):
            failed_indices.append(index)
            continue
        if isinstance(result, dict) and not result.get("success"):
            failed_indices.append(index)
    return failed_indices


def should_skip_failed_retry(result: dict) -> bool:
    """判断失败结果是否应跳过 failed retry，避免放大 Linux.do 限流"""
    if not isinstance(result, dict) or result.get("success"):
        return False

    error_type = result.get("error_type", "")
    if error_type in {
        "linuxdo_prewarmed_state_missing",
        "linuxdo_prewarmed_state_invalid",
        "linuxdo_circuit_open",
    }:
        return True

    error_text = " ".join(
        str(value)
        for value in [result.get("error_label"), result.get("error_summary"), result.get("error_detail"), result.get("error")]
        if value
    ).lower()
    skip_indicators = [
        "缺少预热态",
        "预热态失效",
        "oauth 熔断",
    ]
    return any(indicator in error_text for indicator in skip_indicators)


def should_enable_linuxdo_backoff_retry(result: dict) -> bool:
    """判断失败结果是否值得做延迟退避重试"""
    if not isinstance(result, dict) or result.get("success"):
        return False

    error_type = result.get("error_type", "")
    if error_type in {
        "linuxdo_high_load",
        "linuxdo_sso_provider_stuck",
        "linuxdo_redirect_login",
        "linuxdo_prewarmed_state_missing",
        "linuxdo_prewarmed_state_invalid",
        "linuxdo_circuit_open",
    }:
        return False
    if error_type in {"linuxdo_cloudflare_challenge"}:
        return True

    error_text = " ".join(
        str(value)
        for value in [result.get("error_summary"), result.get("error_detail"), result.get("error")]
        if value
    ).lower()
    retry_indicators = [
        "high load",
        "cloudflare",
        "挑战页",
        "高负载",
    ]
    return any(indicator in error_text for indicator in retry_indicators)


def collect_linuxdo_backoff_retry_indices(account_results: list) -> list[int]:
    """收集适合做 Linux.do 延迟退避重试的账号索引"""
    retry_indices = []
    for index, result in enumerate(account_results):
        if should_enable_linuxdo_backoff_retry(result):
            retry_indices.append(index)
    return retry_indices


def collect_linuxdo_backoff_retry_indices_for_candidates(account_results: list, candidate_indices: list[int]) -> list[int]:
    """仅针对指定账号索引收集 Linux.do 延迟退避重试账号"""
    retry_indices = []
    for index in candidate_indices:
        if not (0 <= index < len(account_results)):
            continue
        if should_enable_linuxdo_backoff_retry(account_results[index]):
            retry_indices.append(index)
    return retry_indices


def should_defer_failed_retry(result: dict) -> bool:
    """判断失败结果是否应延后到主流程完成后再补跑"""
    if not isinstance(result, dict) or result.get("success"):
        return False
    if should_skip_failed_retry(result):
        return False

    error_type = result.get("error_type", "")
    if error_type in DEFERRED_RETRY_ERROR_TYPES:
        return True

    error_text = " ".join(
        str(value)
        for value in [result.get("error_label"), result.get("error_summary"), result.get("error_detail"), result.get("error")]
        if value
    ).lower()
    deferred_indicators = [
        "cloudflare",
        "challenge",
        "高负载",
        "sso provider page is stuck",
        "sso 卡住",
        "会话失效",
        "auth state",
        "oauth",
        "authorize",
        "headless",
        "browser",
    ]
    return any(indicator in error_text for indicator in deferred_indicators)


def build_final_retry_plan(
    account_results: list,
    candidate_indices: list[int] | None = None,
    already_retried_indices: set[int] | None = None,
) -> tuple[list[int], list[int]]:
    """基于首轮结果构造最终补跑计划，确保每个账号最多只再补跑一次"""
    if candidate_indices is None:
        candidate_indices = list(range(len(account_results)))
    if already_retried_indices is None:
        already_retried_indices = set()

    normal_retry_indices = []
    deferred_retry_indices = []
    for index in candidate_indices:
        if not (0 <= index < len(account_results)):
            continue
        if index in already_retried_indices:
            continue

        result = account_results[index]
        if isinstance(result, Exception):
            normal_retry_indices.append(index)
            continue
        if not isinstance(result, dict) or result.get("success"):
            continue
        if should_skip_failed_retry(result):
            continue
        if should_defer_failed_retry(result):
            deferred_retry_indices.append(index)
        else:
            normal_retry_indices.append(index)

    return normal_retry_indices, deferred_retry_indices


def build_execution_batches(accounts: list, account_indices: list[int] | None = None) -> list[dict]:
    """按 Linux.do 用户分批执行账号，优先执行后展开的 Linux.do 账号批次"""
    batches_by_key = {}
    ordered_keys = []
    selected_indices = list(range(len(accounts))) if account_indices is None else [
        index
        for index in account_indices
        if 0 <= index < len(accounts)
    ]

    for index in selected_indices:
        account_config = accounts[index]
        linuxdo_username = ""
        if account_config.linux_do:
            linuxdo_username = account_config.linux_do.get("username", "")

        if linuxdo_username:
            batch_key = f"linuxdo:{linuxdo_username}"
            batch_label = f"Linux.do {mask_linuxdo_username(linuxdo_username)}"
        else:
            batch_key = f"account:{index}"
            batch_label = account_config.get_display_name(index)

        if batch_key not in batches_by_key:
            ordered_keys.append(batch_key)
            slot_label = extract_account_slot_label(account_config.get_display_name(index))
            if linuxdo_username and slot_label:
                batch_label = f"Linux.do {linuxdo_username} ({slot_label})"
            batches_by_key[batch_key] = {
                "key": batch_key,
                "label": batch_label,
                "linuxdo_username": linuxdo_username or None,
                "indices": [],
                "first_index": index,
                "slot_label": slot_label,
            }

        batches_by_key[batch_key]["indices"].append(index)

    def sort_batch_indices(indices: list[int]) -> list[int]:
        def sort_key(index: int) -> tuple[int, int]:
            provider_name = accounts[index].provider
            if provider_name == 'anyrouter':
                priority = 0
            elif provider_name == 'x666':
                priority = 2
            else:
                priority = 1
            return (priority, index)

        return sorted(indices, key=sort_key)

    for batch in batches_by_key.values():
        batch["indices"] = sort_batch_indices(batch["indices"])

    # Linux.do 批次按首次出现位置倒序执行：
    # 在 site-1 / site-2 的账号展开模型下，会先跑完整批 -2，再跑完整批 -1。
    linuxdo_batches = []
    other_batches = []
    for key in ordered_keys:
        batch = batches_by_key[key]
        if batch["linuxdo_username"]:
            linuxdo_batches.append(batch)
        else:
            other_batches.append(batch)

    batch_order = os.getenv("LINUXDO_BATCH_ORDER", "descending").strip().lower()
    reverse_order = batch_order != "ascending"
    linuxdo_batches.sort(key=lambda batch: batch["first_index"], reverse=reverse_order)
    other_batches.sort(key=lambda batch: batch["first_index"])
    return linuxdo_batches + other_batches


def merge_prewarm_summary(overall_summary: dict, batch_summary: dict | None) -> dict:
    """合并批次级 Linux.do 预热摘要"""
    if not batch_summary:
        return overall_summary

    overall_summary["attempted"] += batch_summary.get("attempted", 0)
    overall_summary["successful"] += batch_summary.get("successful", 0)
    overall_summary["failed"] += batch_summary.get("failed", 0)
    overall_summary["issues"].extend(batch_summary.get("issues", []))
    return overall_summary


def clear_linuxdo_runtime_state(reason: str):
    """清理进程内 Linux.do 运行态，隔离下一批账号"""
    print(f"\n🧹 Clearing Linux.do runtime state: {reason}")
    LinuxDoSessionManager.clear_all_sessions()
    LinuxDoSessionManager.clear_all_circuits()


def get_github_skip_prewarm_slot_labels() -> set[str]:
    """获取 GitHub 环境下需要跳过预热的账号槽位标识"""
    raw_value = os.getenv("LINUXDO_GITHUB_SKIP_PREWARM_SLOT_LABELS")
    if raw_value is None and os.getenv("GITHUB_ACTIONS", "").lower() == "true":
        raw_value = "-2"

    if not raw_value:
        return set()

    return {
        item.strip()
        for item in raw_value.split(",")
        if item.strip()
    }


def should_skip_linuxdo_prewarm_for_batch(batch: dict) -> bool:
    """判断当前批次是否应跳过 Linux.do 预热校验"""
    slot_label = batch.get("slot_label")
    if not slot_label:
        return False
    return slot_label in get_github_skip_prewarm_slot_labels()


def purge_site_auth_caches(storage_dir: str = "storage-states") -> list[str]:
    """清理站点侧登录缓存，保留 Linux.do 预热态，尽量模拟首次运行"""
    if os.getenv("PURGE_SITE_AUTH_CACHES_PER_BATCH", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return []

    if not os.path.isdir(storage_dir):
        return []

    deleted = []
    for filename in sorted(os.listdir(storage_dir)):
        if filename.startswith("linuxdo_"):
            continue
        if (
            fnmatch(filename, "provider_*_session.json")
            or fnmatch(filename, "*_linuxdo_*_storage_state.json")
            or fnmatch(filename, "github_*_storage_state.json")
        ):
            file_path = os.path.join(storage_dir, filename)
            try:
                os.remove(file_path)
                deleted.append(filename)
            except FileNotFoundError:
                continue
    return deleted


def build_oauth_probe_payload(
    username: str,
    account_name: str,
    provider_name: str,
    provider_origin: str,
    client_id: str,
) -> dict:
    """构造 Linux.do OAuth 预热探针"""
    slot_label = extract_account_slot_label(account_name) or ""
    state_seed = f"{username}:{provider_name}:{slot_label or 'default'}"
    state = f"prewarm-{hashlib.sha1(state_seed.encode('utf-8')).hexdigest()[:12]}"
    return {
        "label": f"{provider_name}{slot_label}",
        "provider_name": provider_name,
        "client_id": client_id,
        "provider_origin": provider_origin,
        "state": state,
    }


def get_default_linuxdo_oauth_probe(app_config: AppConfig, username: str) -> dict | None:
    """获取默认 Linux.do OAuth 探针，优先选择 anyrouter"""
    preferred_provider_names = ["anyrouter", *sorted(app_config.providers.keys())]
    seen = set()
    for provider_name in preferred_provider_names:
        if provider_name in seen:
            continue
        seen.add(provider_name)
        provider = app_config.get_provider(provider_name)
        if not provider or not provider.linuxdo_client_id:
            continue
        return build_oauth_probe_payload(
            username=username,
            account_name=provider_name,
            provider_name=provider.name,
            provider_origin=provider.origin,
            client_id=provider.linuxdo_client_id,
        )
    return None


def collect_linuxdo_oauth_probes_for_indices(app_config: AppConfig, account_indices: list[int] | None = None) -> dict[str, list[dict]]:
    """为指定账号范围收集 Linux.do OAuth 预热探针"""
    if account_indices is None:
        account_indices = list(range(len(app_config.accounts)))

    probes_by_username: dict[str, list[dict]] = {}
    seen_probe_keys: dict[str, set[tuple[str, str]]] = {}

    for index in account_indices:
        if not (0 <= index < len(app_config.accounts)):
            continue

        account_config = app_config.accounts[index]
        if not account_config.linux_do:
            continue

        username = account_config.linux_do.get("username", "")
        if not username:
            continue

        provider = app_config.get_provider(account_config.provider)
        if not provider or not provider.linuxdo_client_id:
            continue

        account_name = account_config.get_display_name(index)
        probe_key = (provider.linuxdo_client_id, provider.origin)
        user_seen_probe_keys = seen_probe_keys.setdefault(username, set())
        if probe_key in user_seen_probe_keys:
            continue

        probes_by_username.setdefault(username, []).append(
            build_oauth_probe_payload(
                username=username,
                account_name=account_name,
                provider_name=provider.name,
                provider_origin=provider.origin,
                client_id=provider.linuxdo_client_id,
            )
        )
        user_seen_probe_keys.add(probe_key)

    for username in {
        app_config.accounts[index].linux_do.get("username", "")
        for index in account_indices
        if 0 <= index < len(app_config.accounts) and app_config.accounts[index].linux_do
    }:
        if not username:
            continue
        if probes_by_username.get(username):
            continue
        default_probe = get_default_linuxdo_oauth_probe(app_config, username)
        if default_probe:
            probes_by_username[username] = [default_probe]

    preferred_provider_order = {
        "anyrouter": 0,
        "x666": 1,
    }
    max_probe_count = max(1, int(os.getenv("MAX_LINUXDO_PREWARM_PROBES", "1")))
    for username, probes in probes_by_username.items():
        ordered_probes = sorted(
            probes,
            key=lambda probe: (
                preferred_provider_order.get(probe.get("provider_name", ""), 100),
                probe.get("label", ""),
            ),
        )
        probes_by_username[username] = ordered_probes[:max_probe_count]

    return probes_by_username


async def prewarm_linuxdo_sessions(
    app_config: AppConfig,
    account_indices: list[int] | None = None,
    reason: str = "Pre-logging in",
) -> dict:
    """预热指定账号范围内的 Linux.do 会话"""
    accounts = app_config.accounts if hasattr(app_config, "accounts") else list(app_config)
    global_proxy = getattr(app_config, "global_proxy", None)

    selected_indices = list(range(len(accounts))) if account_indices is None else [
        index
        for index in account_indices
        if 0 <= index < len(accounts)
    ]
    selected_accounts = [
        accounts[index]
        for index in selected_indices
        if 0 <= index < len(accounts)
    ]

    linuxdo_credentials = {}
    if hasattr(app_config, "accounts"):
        oauth_probes_by_username = collect_linuxdo_oauth_probes_for_indices(app_config, selected_indices)
    else:
        oauth_probes_by_username = {}

    for account_config in selected_accounts:
        if not account_config.linux_do:
            continue

        username = account_config.linux_do.get("username")
        password = account_config.linux_do.get("password")
        if not username or not password or username in linuxdo_credentials:
            continue

        linuxdo_credentials[username] = {
            "password": password,
            "proxy": account_config.proxy or global_proxy,
            "oauth_probes": oauth_probes_by_username.get(username, []),
        }

    if not linuxdo_credentials:
        print(f"ℹ️ {reason}: no Linux.do accounts need warm-up")
        return {"attempted": 0, "successful": 0, "failed": 0, "issues": []}

    print(f"\n🔐 {reason} {len(linuxdo_credentials)} unique Linux.do account(s)...")
    prelogin_semaphore = asyncio.Semaphore(MAX_CONCURRENT_LINUXDO_PRELOGIN)

    async def prelogin_one(username: str, password: str, proxy, oauth_probes: list[dict]):
        async with prelogin_semaphore:
            try:
                session_kwargs = {
                    "proxy": proxy,
                    "auto_login": True,
                }
                if oauth_probes:
                    session_kwargs["oauth_probes"] = oauth_probes

                session = await LinuxDoSessionManager.get_session(
                    username,
                    password,
                    **session_kwargs,
                )
                if getattr(session, "is_logged_in", False):
                    return username, True, None, None

                storage_state_path = getattr(session, "storage_state_path", "")
                storage_exists = bool(storage_state_path and os.path.exists(storage_state_path))
                issue_type = "linuxdo_prewarmed_state_invalid" if storage_exists else "linuxdo_prewarmed_state_missing"
                issue_summary = (
                    "Linux.do 预热会话已失效，请重新预热"
                    if storage_exists
                    else "Linux.do 预热会话不存在，请先重新预热"
                )
                return username, False, issue_summary, issue_type
            except Exception as e:
                return username, False, str(e), "linuxdo_prewarmed_state_invalid"

    prelogin_results = await asyncio.gather(
        *(
            prelogin_one(username, config["password"], config["proxy"], config.get("oauth_probes", []))
            for username, config in linuxdo_credentials.items()
        )
    )

    success_count = 0
    failed_count = 0
    issues = []
    for username, success, error_msg, issue_type in prelogin_results:
        if success:
            success_count += 1
        else:
            failed_count += 1
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            masked_username = mask_linuxdo_username(username)
            issue_payload = {
                "username_hash": username_hash,
                "username_mask": masked_username,
                "error_type": issue_type,
                "error_summary": error_msg,
                "error_detail": error_msg,
                "error": error_msg,
            }
            issues.append(issue_payload)
            if error_msg:
                print(f"⚠️ LinuxDo prewarm issue [{masked_username}|{username_hash}]: {error_msg}")
            else:
                print(f"⚠️ LinuxDo prewarm issue [{masked_username}|{username_hash}]: login not confirmed")

    print(
        f"✅ {reason} completed, "
        f"{success_count}/{len(linuxdo_credentials)} session(s) ready, "
        f"{LinuxDoSessionManager.get_session_count()} cached\n"
    )
    return {
        "attempted": len(linuxdo_credentials),
        "successful": success_count,
        "failed": failed_count,
        "issues": issues,
    }


def should_enable_bypass_toggle_retry(result: dict, app_config: AppConfig) -> bool:
    """判断失败结果是否应切换当前 bypass 模式后重试"""
    provider_name = result.get("provider", "")
    provider = app_config.get_provider(provider_name)
    site_definition = app_config.site_definitions.get(provider_name)
    if not provider or not site_definition:
        return False
    if site_definition.mode in {"turnstile", "special", "signed"}:
        return False

    error_type = result.get("error_type", "")
    if error_type in {
        "linuxdo_redirect_login",
        "linuxdo_sso_provider_stuck",
        "linuxdo_cloudflare_challenge",
        "linuxdo_auth_state_failed",
    }:
        return True

    error_text = " ".join(
        str(value)
        for value in [
            result.get("error_label"),
            result.get("error_summary"),
            result.get("error_detail"),
            result.get("error"),
        ]
        if value
    ).lower()
    bypass_indicators = [
        "http 403",
        "403",
        "无权进行此操作",
        "未登录且未提供 access token",
        "without access token",
        "会话失效",
        "sso 卡住",
        "cloudflare",
        "challenge",
        "auth state 403",
        "auth state html",
        "text/html",
        "invalid response type",
    ]
    return any(indicator in error_text for indicator in bypass_indicators)


def get_toggled_bypass_method(provider) -> str | None:
    """基于当前 provider 返回切换后的 bypass 配置"""
    return None if provider.needs_waf_cookies() else "waf_cookies"


def get_bypass_mode_label(bypass_method: str | None) -> str:
    """返回便于日志输出的 bypass 模式描述"""
    return "WAF browser mode" if bypass_method == "waf_cookies" else "non-WAF HTTP mode"


def apply_bypass_runtime_overrides_for_failed_accounts(account_results: list, app_config: AppConfig) -> list[str]:
    """为失败站点自动切换 bypass 模式并写入运行时覆盖"""
    updated_providers = []
    seen = set()
    toggled_providers = getattr(app_config, "bypass_toggle_retry_applied", None)
    if toggled_providers is None:
        toggled_providers = set()
        setattr(app_config, "bypass_toggle_retry_applied", toggled_providers)

    for result in account_results:
        if not isinstance(result, dict) or result.get("success"):
            continue
        provider_name = result.get("provider", "")
        if not provider_name or provider_name in seen:
            continue
        if provider_name in toggled_providers:
            continue
        if not should_enable_bypass_toggle_retry(result, app_config):
            continue

        provider = app_config.get_provider(provider_name)
        if not provider:
            continue

        next_bypass_method = get_toggled_bypass_method(provider)
        overrides = {"bypass_method": next_bypass_method}
        update_runtime_site_override(app_config.runtime_sites_file, provider_name, overrides)
        app_config.update_provider(provider_name, provider.apply_overrides(overrides))
        updated_providers.append(provider_name)
        toggled_providers.add(provider_name)
        seen.add(provider_name)
        print(
            f"🔧 Auto-toggled {provider_name} to {get_bypass_mode_label(next_bypass_method)} "
            "due to auth-style failure"
        )

    return updated_providers


async def rerun_failed_accounts_once(account_results: list, app_config, semaphore: asyncio.Semaphore) -> list:
    """对失败账号补跑一轮，并用补跑结果覆盖原结果"""
    failed_indices, _ = build_final_retry_plan(account_results)

    skipped_retry_indices = [
        index
        for index in collect_failed_account_indices(account_results)
        if index < len(account_results)
        and isinstance(account_results[index], dict)
        and should_skip_failed_retry(account_results[index])
    ]
    if skipped_retry_indices:
        print(
            f"ℹ️ Retrying failed account(s) once: skipping {len(skipped_retry_indices)} account(s) "
            "with Linux.do high-load/SSO-stuck errors"
        )

    return await rerun_selected_accounts(
        account_results,
        app_config,
        semaphore,
        failed_indices,
        retry_reason="Retrying failed account(s) once",
    )


async def rerun_failed_accounts_once_for_candidates(
    account_results: list,
    app_config,
    semaphore: asyncio.Semaphore,
    candidate_indices: list[int],
    retry_reason: str,
    already_retried_indices: set[int] | None = None,
) -> list:
    """仅对指定批次中的失败账号补跑一轮"""
    failed_indices, _ = build_final_retry_plan(
        account_results,
        candidate_indices,
        already_retried_indices=already_retried_indices,
    )

    skipped_retry_indices = [
        index
        for index in collect_failed_account_indices_for_candidates(account_results, candidate_indices)
        if index < len(account_results)
        and isinstance(account_results[index], dict)
        and should_skip_failed_retry(account_results[index])
    ]
    if skipped_retry_indices:
        print(
            f"ℹ️ {retry_reason}: skipping {len(skipped_retry_indices)} account(s) "
            "with Linux.do high-load/SSO-stuck errors"
        )

    return await rerun_selected_accounts(
        account_results,
        app_config,
        semaphore,
        failed_indices,
        retry_reason=retry_reason,
    )


async def rerun_selected_accounts(
    account_results: list,
    app_config,
    semaphore: asyncio.Semaphore,
    failed_indices: list[int],
    retry_reason: str,
) -> list:
    """对指定账号索引补跑一轮，并用补跑结果覆盖原结果"""
    if not failed_indices:
        print(f"ℹ️ {retry_reason}: no accounts to retry")
        return account_results

    selected_results = [
        account_results[index]
        for index in failed_indices
        if index < len(account_results) and isinstance(account_results[index], dict)
    ]
    updated_providers = apply_bypass_runtime_overrides_for_failed_accounts(selected_results, app_config)
    if updated_providers:
        print(f"⚙️ Runtime bypass overrides applied for {len(updated_providers)} provider(s): {updated_providers}")

    print(f"\n🔁 {retry_reason}: retrying {len(failed_indices)} account(s)...")
    retry_tasks = [
        process_single_account(index, app_config.accounts[index], app_config, semaphore)
        for index in failed_indices
    ]
    retry_results = await asyncio.gather(*retry_tasks, return_exceptions=True)

    recovered_count = 0
    for index, retry_result in zip(failed_indices, retry_results):
        original_result = account_results[index]
        account_results[index] = retry_result
        if (
            isinstance(retry_result, dict)
            and retry_result.get("success")
            and (
                isinstance(original_result, Exception)
                or (isinstance(original_result, dict) and not original_result.get("success"))
            )
        ):
            recovered_count += 1

    print(f"✅ {retry_reason} finished, recovered {recovered_count}/{len(failed_indices)} account(s)")
    return account_results


async def rerun_deferred_accounts_once(
    account_results: list,
    app_config,
    candidate_indices: list[int],
    already_retried_indices: set[int],
) -> list:
    """将慢错误账号延后到主流程完成后统一补跑一次"""
    _, deferred_retry_indices = build_final_retry_plan(
        account_results,
        candidate_indices,
        already_retried_indices=already_retried_indices,
    )
    if not deferred_retry_indices:
        print("ℹ️ Deferred retry stage: no slow-failure accounts to retry")
        return account_results

    print(
        f"\n🕓 Deferred retry stage: retrying {len(deferred_retry_indices)} slow-failure account(s) "
        "after the main flow"
    )
    if DEFERRED_RETRY_DELAY_SECONDS > 0:
        print(f"⏳ Deferred retry stage: waiting {DEFERRED_RETRY_DELAY_SECONDS}s before retry")
        await asyncio.sleep(DEFERRED_RETRY_DELAY_SECONDS)

    await prewarm_linuxdo_sessions(
        app_config,
        account_indices=deferred_retry_indices,
        reason="Pre-logging in for deferred retry stage",
    )
    deferred_semaphore = asyncio.Semaphore(min(MAX_CONCURRENT_DEFERRED_RETRY, MAX_CONCURRENT_ACCOUNTS))
    account_results = await rerun_selected_accounts(
        account_results,
        app_config,
        deferred_semaphore,
        deferred_retry_indices,
        retry_reason="Deferred retry stage",
    )
    already_retried_indices.update(deferred_retry_indices)
    return account_results


def get_site_label(provider_name: str, site_origin: str | None = None) -> str:
    """获取站点展示名称"""
    if site_origin:
        host = urlparse(site_origin).netloc
        if host:
            return host
    return provider_name or "unknown-site"


def build_site_notification_groups(sorted_results: list[dict]) -> list[dict]:
    """按站点聚合通知内容"""
    grouped_results = []

    for provider, group in groupby(sorted_results, key=lambda x: x.get("provider", "")):
        site_results = list(group)
        site_origin = next((item.get("site_origin") for item in site_results if item.get("site_origin")), "")
        site_label = get_site_label(provider, site_origin)
        total_accounts = len(site_results)
        success_accounts = sum(1 for item in site_results if item.get("success"))

        detail_parts = []
        success_detail_parts = []
        for item in site_results:
            status = item.get("status")
            if status == "failed":
                reason = item.get("error_label") or item.get("error_summary") or item.get("error") or "未知错误"
                detail_parts.append(f"{item['account_name']}: {str(reason)[:40]}")
            elif status == "partial":
                failed_methods = ", ".join(item.get("failed_methods") or [])
                failed_reason = item.get("error_label") or item.get("error_summary")
                if failed_methods:
                    if failed_reason:
                        detail_parts.append(f"{item['account_name']}: 部分失败({failed_methods}, {failed_reason})")
                    else:
                        detail_parts.append(f"{item['account_name']}: 部分失败({failed_methods})")
                else:
                    detail_parts.append(f"{item['account_name']}: 部分失败")
            elif item.get("success_detail") and provider in {"x666", "anyrouter"}:
                success_detail_parts.append(f"{item['account_name']}: {item['success_detail']}")

        if success_accounts == total_accounts and not detail_parts:
            icon = "✅"
        elif success_accounts > 0:
            icon = "⚠️"
        else:
            icon = "❌"

        line = f"{icon} {site_label}: {success_accounts}/{total_accounts} 账号签到成功"
        if success_detail_parts:
            line = f"{line} | {'；'.join(success_detail_parts[:2])}"
        if detail_parts:
            brief = "；".join(detail_parts[:2])
            if len(detail_parts) > 2:
                brief += f"；其余 {len(detail_parts) - 2} 个账号请看日志"
            line = f"{line} | {brief}"

        grouped_results.append(
            {
                "provider": provider,
                "site_label": site_label,
                "line": line,
                "success_accounts": success_accounts,
                "total_accounts": total_accounts,
            }
        )

    return grouped_results


async def main():
    """运行签到流程

    Returns:
            退出码: 0 表示至少有一个账号成功, 1 表示全部失败
    """

    print("🚀 newapi.ai multi-account auto check-in script started (using Camoufox)")
    print(f'🕒 Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

    clear_linuxdo_runtime_state("startup")

    app_config = AppConfig.load_from_env()
    setattr(app_config, "bypass_toggle_retry_applied", set())
    print(f"⚙️ Loaded {len(app_config.providers)} provider(s)")
    print(
        "⚙️ Effective concurrency: "
        f"accounts={MAX_CONCURRENT_ACCOUNTS}, "
        f"runtime_discovery={MAX_CONCURRENT_RUNTIME_DISCOVERY}, "
        f"linuxdo_prewarm={MAX_CONCURRENT_LINUXDO_PRELOGIN}, "
        f"deferred_retry={MAX_CONCURRENT_DEFERRED_RETRY}, "
        f"linuxdo_oauth={os.getenv('MAX_CONCURRENT_LINUXDO_OAUTH', os.getenv('MAX_CONCURRENT_ACCOUNTS', '10'))}, "
        f"serialize_same_linuxdo_oauth={os.getenv('SERIALIZE_SAME_LINUXDO_OAUTH', 'false')}"
    )

    # 检查账号配置
    if not app_config.accounts:
        print("❌ Unable to load account configuration, program exits")
        return 1

    print(f"⚙️ Found {len(app_config.accounts)} account(s)")

    discovered_runtime_overrides = await ensure_runtime_site_overrides(app_config, max_concurrency=MAX_CONCURRENT_RUNTIME_DISCOVERY)
    if discovered_runtime_overrides:
        print(f"⚙️ Runtime site overrides updated for {len(discovered_runtime_overrides)} site(s)")

    # 加载余额hash
    last_balance_hash = load_balance_hash(BALANCE_HASH_FILE)
    now_ts = int(datetime.now().timestamp())
    recent_success_state = load_recent_success_state(RECENT_SUCCESS_STATE_FILE)
    recent_success_skip_results = collect_recent_success_skip_results(app_config, recent_success_state, now_ts)
    runnable_indices = [
        index
        for index in range(len(app_config.accounts))
        if index not in recent_success_skip_results
    ]

    if recent_success_skip_results:
        print(
            f"⏭️ Skipping {len(recent_success_skip_results)} account(s) that succeeded within "
            f"the last {RECENT_SUCCESS_SKIP_TTL_SECONDS // 3600} hour(s)"
        )
        for index in sorted(recent_success_skip_results):
            account_name = app_config.accounts[index].get_display_name(index)
            print(f"  • {account_name}")

    execution_batches = build_execution_batches(app_config.accounts, runnable_indices)
    print(f"⚙️ Built {len(execution_batches)} execution batch(es)")
    for batch_index, batch in enumerate(execution_batches, start=1):
        print(
            f"  • Batch {batch_index}: {batch['label']} "
            f"({len(batch['indices'])} account(s))"
        )

    # 分批处理所有账号，避免同站点连续切换 Linux.do 双账号授权
    print(f"\n🚀 Starting batched processing with max {MAX_CONCURRENT_ACCOUNTS} concurrent accounts...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_ACCOUNTS)
    account_results: list = [None] * len(app_config.accounts)
    for index, skip_result in recent_success_skip_results.items():
        account_results[index] = skip_result
    prewarm_summary = {"attempted": 0, "successful": 0, "failed": 0, "issues": []}
    retried_account_indices: set[int] = set()

    for batch_index, batch in enumerate(execution_batches, start=1):
        batch_indices = batch["indices"]
        batch_label = batch["label"]
        print(
            f"\n🧩 Starting batch {batch_index}/{len(execution_batches)}: "
            f"{batch_label} -> {len(batch_indices)} account(s)"
        )
        ordered_account_names = [app_config.accounts[index].get_display_name(index) for index in batch_indices]
        print(f"ℹ️ {batch_label} execution order: {', '.join(ordered_account_names[:10])}")

        cleared_site_caches = purge_site_auth_caches()
        if cleared_site_caches:
            print(
                f"🧹 Cleared {len(cleared_site_caches)} site auth cache file(s) before batch {batch_label}"
            )

        if should_skip_linuxdo_prewarm_for_batch(batch):
            print(
                f"🧹 Skipping LinuxDo prewarm verification for batch {batch_label} on GitHub, "
                "preserving restored prewarmed storage state"
            )
            batch_prewarm_summary = {"attempted": 0, "successful": 0, "failed": 0, "issues": []}
        else:
            batch_prewarm_summary = await prewarm_linuxdo_sessions(
                app_config,
                account_indices=batch_indices,
                reason=f"Pre-logging in for batch {batch_index}/{len(execution_batches)} [{batch_label}]",
            )
        merge_prewarm_summary(prewarm_summary, batch_prewarm_summary)

        tasks = [
            process_single_account(i, app_config.accounts[i], app_config, semaphore)
            for i in batch_indices
        ]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for index, result in zip(batch_indices, batch_results):
            account_results[index] = result

        if batch_index < len(execution_batches):
            clear_linuxdo_runtime_state(f"after batch {batch_index}/{len(execution_batches)} [{batch_label}]")

    if MAX_FAILED_RETRY_ROUNDS > 0:
        clear_linuxdo_runtime_state("before final normal retry phase")
        for retry_round in range(1, MAX_FAILED_RETRY_ROUNDS + 1):
            normal_retry_indices, _ = build_final_retry_plan(
                account_results,
                runnable_indices,
                already_retried_indices=retried_account_indices,
            )
            if not normal_retry_indices:
                break
            print(
                f"\n🔁 Final normal retry round {retry_round}/{MAX_FAILED_RETRY_ROUNDS}: "
                f"{len(normal_retry_indices)} account(s)"
            )
            account_results = await rerun_selected_accounts(
                account_results,
                app_config,
                semaphore,
                normal_retry_indices,
                retry_reason=f"Final normal retry round {retry_round}",
            )
            retried_account_indices.update(normal_retry_indices)

    if MAX_DEFERRED_RETRY_ROUNDS > 0:
        deferred_semaphore = asyncio.Semaphore(MAX_CONCURRENT_DEFERRED_RETRY)
        clear_linuxdo_runtime_state("before deferred slow retry phase")
        deferred_cleared_site_caches = purge_site_auth_caches()
        if deferred_cleared_site_caches:
            print(
                f"🧹 Cleared {len(deferred_cleared_site_caches)} site auth cache file(s) "
                "before deferred slow retry phase"
            )
        for retry_round in range(1, MAX_DEFERRED_RETRY_ROUNDS + 1):
            _, deferred_retry_indices = build_final_retry_plan(
                account_results,
                runnable_indices,
                already_retried_indices=retried_account_indices,
            )
            if not deferred_retry_indices:
                break
            if DEFERRED_RETRY_DELAY_SECONDS > 0:
                print(
                    f"⏳ Deferred slow retry round {retry_round}/{MAX_DEFERRED_RETRY_ROUNDS}: "
                    f"waiting {DEFERRED_RETRY_DELAY_SECONDS}s before retrying {len(deferred_retry_indices)} account(s)"
                )
                await asyncio.sleep(DEFERRED_RETRY_DELAY_SECONDS)
            else:
                print(
                    f"\n🐢 Deferred slow retry round {retry_round}/{MAX_DEFERRED_RETRY_ROUNDS}: "
                    f"{len(deferred_retry_indices)} account(s)"
                )

            await prewarm_linuxdo_sessions(
                app_config,
                account_indices=deferred_retry_indices,
                reason=f"Pre-logging in for deferred slow retry round {retry_round}",
            )
            account_results = await rerun_selected_accounts(
                account_results,
                app_config,
                deferred_semaphore,
                deferred_retry_indices,
                retry_reason=f"Deferred slow retry round {retry_round}",
            )
            retried_account_indices.update(deferred_retry_indices)

    recent_success_state = update_recent_success_state_from_results(
        recent_success_state,
        account_results,
        app_config,
        now_ts,
    )
    save_recent_success_state(RECENT_SUCCESS_STATE_FILE, recent_success_state)

    # 汇总结果
    current_balances = {}
    need_notify = False

    # 按账号索引排序结果，确保通知顺序一致
    sorted_results = sorted(
        [r for r in account_results if isinstance(r, dict)],
        key=lambda x: x.get("account_index", 0)
    )

    for result in sorted_results:
        # 收集余额信息
        if result.get("success") and result.get("balances"):
            current_balances[result["account_key"]] = result["balances"]

        # 检查是否需要通知
        if result.get("need_notify"):
            need_notify = True

    grouped_notifications = build_site_notification_groups(sorted_results)
    notification_lines = [item["line"] for item in grouped_notifications]
    linuxdo_prewarm_alert_lines = build_linuxdo_prewarm_alert_lines(prewarm_summary, sorted_results)
    if linuxdo_prewarm_alert_lines:
        need_notify = True
        notification_lines.extend(linuxdo_prewarm_alert_lines)
        print("\n".join(linuxdo_prewarm_alert_lines))

    # 处理异常结果
    for result in account_results:
        if isinstance(result, Exception):
            need_notify = True
            notification_lines.append(f"❌ 异常: {str(result)[:80]}")

    # 检查余额变化
    current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
    print(f"\n\nℹ️ Current balance hash: {current_balance_hash}, Last balance hash: {last_balance_hash}")
    if current_balance_hash:
        if last_balance_hash is None:
            need_notify = True
            print("🔔 First run detected, will send notification with current balances")
        elif current_balance_hash != last_balance_hash:
            need_notify = True
            print("🔔 Balance changes detected, will send notification")
        else:
            print("ℹ️ No balance changes detected")

    # 保存当前余额hash
    if current_balance_hash:
        save_balance_hash(BALANCE_HASH_FILE, current_balance_hash)

    if need_notify and notification_lines:
        # 构建通知内容
        total_accounts = len(sorted_results)
        success_accounts = sum(1 for result in sorted_results if result.get("success"))
        total_sites = len(grouped_notifications)
        success_sites = sum(
            1 for item in grouped_notifications if item["success_accounts"] == item["total_accounts"]
        )

        if success_accounts == total_accounts:
            status_icon = "✅"
        elif success_accounts > 0:
            status_icon = "⚠️"
        else:
            status_icon = "❌"
        summary_line = (
            f"📊 站点全成功 {success_sites}/{total_sites} | "
            f"账号成功 {success_accounts}/{total_accounts} {status_icon}"
        )

        time_info = f'⏰ {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

        notify_content = time_info + "\n\n" + "\n".join(notification_lines) + "\n\n" + summary_line

        print(notify_content)
        notify.push_message("签到通知", notify_content, msg_type="text")
        print("🔔 Notification sent due to failures or balance changes")
    else:
        print("ℹ️ All accounts successful and no balance changes detected, notification skipped")

    # 设置退出码
    success_accounts = sum(1 for result in sorted_results if result.get("success"))
    sys.exit(0 if success_accounts > 0 else 1)


def run_main():
    """运行主函数的包装函数"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️ Program interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error occurred during program execution: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_main()
