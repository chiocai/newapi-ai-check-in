#!/usr/bin/env python3
"""
手工预热 Linux.do 登录会话
"""

import argparse
import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv

from utils.linuxdo_session import LinuxDoSession


def load_linuxdo_accounts() -> list[dict]:
    """从环境变量加载去重后的 Linux.do 账号"""
    for dotenv_name in [".env", ".env.local"]:
        dotenv_path = Path(dotenv_name)
        if dotenv_path.exists():
            load_dotenv(dotenv_path=dotenv_path, override=True)

    accounts_str = os.getenv("ACCOUNTS")
    if not accounts_str:
        raise RuntimeError("ACCOUNTS environment variable not found")

    accounts_data = json.loads(accounts_str)
    found = {}

    if isinstance(accounts_data, dict):
        for item in accounts_data.get("linux.do", []):
            if isinstance(item, dict) and item.get("username") and item.get("password"):
                found[item["username"]] = item

        for item in accounts_data.get("accounts", []):
            if not isinstance(item, dict):
                continue
            linux_do = item.get("linux.do")
            if isinstance(linux_do, dict) and linux_do.get("username") and linux_do.get("password"):
                found[linux_do["username"]] = linux_do
    elif isinstance(accounts_data, list):
        for item in accounts_data:
            if not isinstance(item, dict):
                continue
            linux_do = item.get("linux.do")
            if isinstance(linux_do, dict) and linux_do.get("username") and linux_do.get("password"):
                found[linux_do["username"]] = linux_do

    return list(found.values())


async def main():
    parser = argparse.ArgumentParser(description="Open visible browser and warm up Linux.do session cache")
    parser.add_argument("--username", help="Only warm up the specified Linux.do username")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout seconds for each manual warm-up")
    args = parser.parse_args()

    accounts = load_linuxdo_accounts()
    if args.username:
        accounts = [item for item in accounts if item.get("username") == args.username]

    if not accounts:
        print("❌ No Linux.do accounts found to warm up")
        return 1

    print(f"🔐 Preparing {len(accounts)} Linux.do session(s) manually...")

    success_count = 0
    for item in accounts:
        username = item["username"]
        password = item["password"]
        session = LinuxDoSession(username, password)
        print(f"\n🌐 Manual warm-up for {username}")
        print("请在弹出的浏览器中完成 Linux.do 登录与验证，脚本会自动检测成功并保存会话。")
        ok = await session.prepare_manually(timeout_seconds=args.timeout)
        if ok:
            success_count += 1

    print(f"\n📊 Manual warm-up finished: {success_count}/{len(accounts)} successful")
    return 0 if success_count == len(accounts) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
