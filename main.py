#!/usr/bin/env python3
"""
自动签到脚本
"""

import asyncio
import hashlib
import json
import sys
from datetime import datetime
from itertools import groupby
from urllib.parse import urlparse

from dotenv import load_dotenv

from checkin import CheckIn
from utils.balance_hash import load_balance_hash, save_balance_hash
from utils.config import AppConfig
from utils.linuxdo_session import LinuxDoSessionManager
from utils.notify import notify
from utils.site_discovery import ensure_runtime_site_overrides

load_dotenv(override=True)

BALANCE_HASH_FILE = "balance_hash.txt"

# 并行处理配置
MAX_CONCURRENT_ACCOUNTS = 10  # 最大并发账号数
MAX_CONCURRENT_RUNTIME_DISCOVERY = 10  # 运行时自动发现最大并发数
MAX_CONCURRENT_LINUXDO_PRELOGIN = 2  # LinuxDo 预登录最大并发数
MAX_FAILED_RETRY_ROUNDS = 1  # 全量执行后的失败补跑轮次


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
                    error_msg = user_info.get("error", "未知错误") if user_info else "未知错误"
                    failed_details.append(str(error_msg)[:60])
                    line_parts.append(str(error_msg)[:60])

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
            if account_success and failed_methods:
                result["status"] = "partial"
            elif account_success:
                result["status"] = "success"
            else:
                result["status"] = "failed"
                result["error"] = result["error_summary"] or result["error"]

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


async def rerun_failed_accounts_once(account_results: list, app_config, semaphore: asyncio.Semaphore) -> list:
    """对失败账号补跑一轮，并用补跑结果覆盖原结果"""
    failed_indices = collect_failed_account_indices(account_results)
    if not failed_indices:
        print("ℹ️ No failed accounts to retry")
        return account_results

    print(f"\n🔁 Retrying {len(failed_indices)} failed account(s) once...")
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

    print(f"✅ Retry round finished, recovered {recovered_count}/{len(failed_indices)} failed account(s)")
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
        for item in site_results:
            status = item.get("status")
            if status == "failed":
                reason = item.get("error_summary") or item.get("error") or "未知错误"
                detail_parts.append(f"{item['account_name']}: {str(reason)[:40]}")
            elif status == "partial":
                failed_methods = ", ".join(item.get("failed_methods") or [])
                if failed_methods:
                    detail_parts.append(f"{item['account_name']}: 部分失败({failed_methods})")
                else:
                    detail_parts.append(f"{item['account_name']}: 部分失败")

        if success_accounts == total_accounts and not detail_parts:
            icon = "✅"
        elif success_accounts > 0:
            icon = "⚠️"
        else:
            icon = "❌"

        line = f"{icon} {site_label}: {success_accounts}/{total_accounts} 账号签到成功"
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

    app_config = AppConfig.load_from_env()
    print(f"⚙️ Loaded {len(app_config.providers)} provider(s)")

    # 检查账号配置
    if not app_config.accounts:
        print("❌ Unable to load account configuration, program exits")
        return 1

    print(f"⚙️ Found {len(app_config.accounts)} account(s)")

    discovered_runtime_overrides = await ensure_runtime_site_overrides(app_config, max_concurrency=MAX_CONCURRENT_RUNTIME_DISCOVERY)
    if discovered_runtime_overrides:
        print(f"⚙️ Runtime site overrides updated for {len(discovered_runtime_overrides)} site(s)")

    # 预登录所有 Linux.do 账号（会话共享优化）
    linuxdo_usernames = set()
    for account_config in app_config.accounts:
        if account_config.linux_do:
            username = account_config.linux_do.get("username")
            if username:
                linuxdo_usernames.add(username)

    if linuxdo_usernames:
        print(f"\n🔐 Pre-logging in {len(linuxdo_usernames)} unique Linux.do account(s)...")
        linuxdo_credentials = {}
        for account_config in app_config.accounts:
            if account_config.linux_do:
                username = account_config.linux_do.get("username")
                if username and username not in linuxdo_credentials:
                    linuxdo_credentials[username] = {
                        "password": account_config.linux_do.get("password"),
                        "proxy": account_config.proxy or app_config.global_proxy,
                    }

        prelogin_semaphore = asyncio.Semaphore(MAX_CONCURRENT_LINUXDO_PRELOGIN)

        async def prelogin_one(username: str, password: str, proxy):
            async with prelogin_semaphore:
                try:
                    await LinuxDoSessionManager.get_session(username, password, proxy)
                except Exception as e:
                    print(f"⚠️ Failed to pre-login Linux.do account [{username[:4]}...]: {e}")

        await asyncio.gather(
            *(
                prelogin_one(username, config["password"], config["proxy"])
                for username, config in linuxdo_credentials.items()
            )
        )
        print(f"✅ Linux.do pre-login completed, {LinuxDoSessionManager.get_session_count()} session(s) cached\n")

    # 加载余额hash
    last_balance_hash = load_balance_hash(BALANCE_HASH_FILE)

    # 并行处理所有账号
    print(f"\n🚀 Starting parallel processing with max {MAX_CONCURRENT_ACCOUNTS} concurrent accounts...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_ACCOUNTS)

    # 创建所有账号的处理任务
    tasks = [
        process_single_account(i, account_config, app_config, semaphore)
        for i, account_config in enumerate(app_config.accounts)
    ]

    # 并行执行所有任务
    account_results = await asyncio.gather(*tasks, return_exceptions=True)

    for retry_round in range(MAX_FAILED_RETRY_ROUNDS):
        failed_indices = collect_failed_account_indices(account_results)
        if not failed_indices:
            break
        print(f"ℹ️ Retry round {retry_round + 1}/{MAX_FAILED_RETRY_ROUNDS}")
        account_results = await rerun_failed_accounts_once(account_results, app_config, semaphore)

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
