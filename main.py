#!/usr/bin/env python3
"""
自动签到脚本
"""

import asyncio
import hashlib
import json
import sys
from datetime import datetime
from dotenv import load_dotenv
from utils.config import AppConfig
from utils.notify import notify
from utils.balance_hash import load_balance_hash, save_balance_hash
from utils.linuxdo_session import LinuxDoSessionManager
from checkin import CheckIn

load_dotenv(override=True)

BALANCE_HASH_FILE = "balance_hash.txt"

# 并行处理配置
MAX_CONCURRENT_ACCOUNTS = 4  # 最大并发账号数


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
            "success": False,
            "results": [],
            "balances": {},
            "notification": "",
            "need_notify": False,
            "error": None,
        }

        try:
            provider_config = app_config.get_provider(account_config.provider)
            if not provider_config:
                print(f"❌ {account_name}: Provider '{account_config.provider}' configuration not found")
                result["need_notify"] = True
                result["notification"] = f"[FAIL] {account_name}: Provider '{account_config.provider}' configuration not found"
                result["error"] = f"Provider '{account_config.provider}' not found"
                return result

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
            this_account_balances = {}

            # 构建简化的中文结果报告
            account_result = f"📌 {account_name}\n"
            for auth_method, success, user_info in results:
                if success and user_info and user_info.get("success"):
                    account_success = True
                    successful_methods.append(auth_method)
                    # 记录余额信息
                    if "quota" in user_info:
                        current_quota = user_info["quota"]
                        current_used = user_info["used_quota"]
                        current_bonus = user_info["bonus_quota"]
                        checkin_reward = user_info.get("checkin_reward")

                        if checkin_reward is not None:
                            account_result += f"  ✅ 签到成功 (+${checkin_reward})\n"
                        else:
                            account_result += f"  ✅ 签到成功\n"
                        account_result += f"  💰 余额: ${current_quota} | 已用: ${current_used}\n"
                        this_account_balances[f"{auth_method}"] = {
                            "quota": current_quota,
                            "used": current_used,
                            "bonus": current_bonus,
                        }
                    elif "cdk_results" in user_info:
                        cdk_results = user_info['cdk_results']
                        account_result += f"  ✅ 签到成功\n"
                        for cdk_result in cdk_results:
                            if isinstance(cdk_result, dict):
                                result_type = cdk_result.get("type", "")
                                if result_type == "checkin_success":
                                    quota = cdk_result.get("quota", 0)
                                    balance = cdk_result.get("balance", 0)
                                    account_result += f"  🎰 转盘获得: ${quota}\n"
                                    if balance > 0:
                                        account_result += f"  💰 当前余额: ${balance}\n"
                                elif result_type == "wheel_success":
                                    total_quota = cdk_result.get("total_quota", 0)
                                    spin_count = cdk_result.get("spin_count", 0)
                                    already_done = cdk_result.get("already_done", False)
                                    if already_done:
                                        account_result += f"  🎰 今日已抽 {spin_count} 次, 获得: ${total_quota}\n"
                                    else:
                                        account_result += f"  🎰 转盘 {spin_count} 次, 获得: ${total_quota}\n"
                                elif result_type == "cdk_list":
                                    cdks = cdk_result.get("cdks", [])
                                    total_quota = cdk_result.get("total_quota", 0)
                                    spin_count = cdk_result.get("spin_count", 0)
                                    account_result += f"  🎰 转盘 {spin_count} 次, 获得: ${total_quota}\n"
                                    if cdks:
                                        account_result += f"  🎁 CDK: {len(cdks)} 个待兑换\n"
                        if not any(isinstance(r, dict) for r in cdk_results):
                            account_result += f"  🎁 抽奖完成: {len(cdk_results)} 个结果\n"
                    elif "message" in user_info:
                        account_result += f"  ✅ 签到成功\n"
                        account_result += f"  ℹ️ {user_info['message']}\n"
                    else:
                        account_result += f"  ✅ 签到成功\n"
                else:
                    failed_methods.append(auth_method)
                    error_msg = user_info.get("error", "未知错误") if user_info else "未知错误"
                    account_result += f"  ❌ 签到失败\n"
                    account_result += f"  ⚠️ {str(error_msg)}\n"

            result["success"] = account_success
            result["balances"] = this_account_balances
            result["notification"] = account_result

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
            result["notification"] = f"❌ {account_name} Exception: {str(e)[:100]}..."
            result["error"] = str(e)

        return result


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

    # 预登录所有 Linux.do 账号（会话共享优化）
    linuxdo_usernames = set()
    for account_config in app_config.accounts:
        if account_config.linux_do:
            username = account_config.linux_do.get("username")
            if username:
                linuxdo_usernames.add(username)

    if linuxdo_usernames:
        print(f"\n🔐 Pre-logging in {len(linuxdo_usernames)} unique Linux.do account(s)...")
        for username in linuxdo_usernames:
            # 找到第一个使用该用户名的账号配置，获取密码和代理
            for account_config in app_config.accounts:
                if account_config.linux_do and account_config.linux_do.get("username") == username:
                    password = account_config.linux_do.get("password")
                    proxy = account_config.proxy or app_config.global_proxy
                    try:
                        await LinuxDoSessionManager.get_session(username, password, proxy)
                    except Exception as e:
                        print(f"⚠️ Failed to pre-login Linux.do account [{username[:4]}...]: {e}")
                    break
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

    # 汇总结果
    success_count = 0
    total_count = 0
    notification_content = []
    current_balances = {}
    need_notify = False

    # 按账号索引排序结果，确保通知顺序一致
    sorted_results = sorted(
        [r for r in account_results if isinstance(r, dict)],
        key=lambda x: x.get("account_index", 0)
    )

    for result in sorted_results:
        if len(notification_content) > 0:
            notification_content.append("\n-------------------------------")

        # 统计结果
        for auth_result in result.get("results", []):
            total_count += 1
            if auth_result[1] and auth_result[2] and auth_result[2].get("success"):
                success_count += 1

        # 收集余额信息
        if result.get("success") and result.get("balances"):
            current_balances[result["account_key"]] = result["balances"]

        # 收集通知内容
        if result.get("notification"):
            notification_content.append(result["notification"])

        # 检查是否需要通知
        if result.get("need_notify"):
            need_notify = True

    # 处理异常结果
    for result in account_results:
        if isinstance(result, Exception):
            need_notify = True
            notification_content.append(f"❌ Exception: {str(result)[:100]}...")

    # 检查余额变化
    current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
    print(f"\n\nℹ️ Current balance hash: {current_balance_hash}, Last balance hash: {last_balance_hash}")
    if current_balance_hash:
        if last_balance_hash is None:
            # 首次运行
            need_notify = True
            print("🔔 First run detected, will send notification with current balances")
        elif current_balance_hash != last_balance_hash:
            # 余额有变化
            need_notify = True
            print("🔔 Balance changes detected, will send notification")
        else:
            print("ℹ️ No balance changes detected")

    # 保存当前余额hash
    if current_balance_hash:
        save_balance_hash(BALANCE_HASH_FILE, current_balance_hash)

    if need_notify and notification_content:
        # 构建通知内容
        failed_count = total_count - success_count
        summary = [
            "-------------------------------",
            f"📊 统计: 成功 {success_count}/{total_count}, 失败 {failed_count}/{total_count}",
        ]

        if success_count == total_count:
            summary.append("✅ 全部签到成功")
        elif success_count > 0:
            summary.append("⚠️ 部分签到成功")
        else:
            summary.append("❌ 全部签到失败")

        time_info = f'⏰ {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

        notify_content = "\n\n".join([time_info, "\n".join(notification_content), "\n".join(summary)])

        print(notify_content)
        notify.push_message("签到通知", notify_content, msg_type="text")
        print("🔔 Notification sent due to failures or balance changes")
    else:
        print("ℹ️ All accounts successful and no balance changes detected, notification skipped")

    # 设置退出码
    sys.exit(0 if success_count > 0 else 1)


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
