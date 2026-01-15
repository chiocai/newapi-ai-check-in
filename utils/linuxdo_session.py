#!/usr/bin/env python3
"""
Linux.do 会话管理器

实现 Linux.do 登录会话的共享和复用，避免同一账号重复登录
"""

import hashlib
import json
import os
from typing import TYPE_CHECKING

from camoufox.async_api import AsyncCamoufox
from utils.browser_utils import take_screenshot, save_page_content_to_file

if TYPE_CHECKING:
    pass

# 存储目录
STORAGE_STATE_DIR = "storage-states"


class LinuxDoSession:
    """单个 Linux.do 会话"""

    def __init__(self, username: str, password: str, proxy: dict | None = None):
        """初始化会话

        Args:
            username: Linux.do 用户名
            password: Linux.do 密码
            proxy: 代理配置
        """
        self.username = username
        self.password = password
        self.proxy = proxy
        self.username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        self.storage_state_path = f"{STORAGE_STATE_DIR}/linuxdo_{self.username_hash}_storage_state.json"
        self.is_logged_in = False
        self._storage_state: dict | None = None

        # 确保存储目录存在
        os.makedirs(STORAGE_STATE_DIR, exist_ok=True)

    async def ensure_logged_in(self) -> bool:
        """确保已登录，如果未登录则执行登录

        Returns:
            bool: 登录是否成功
        """
        if self.is_logged_in and self._storage_state:
            print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Already logged in (memory cache)")
            return True

        # 检查是否有缓存文件
        if os.path.exists(self.storage_state_path):
            print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Found cache file, verifying...")
            # 尝试使用缓存验证登录状态
            is_valid = await self._verify_cached_session()
            if is_valid:
                self.is_logged_in = True
                return True
            print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Cache expired, need to re-login")

        # 执行登录
        print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Starting login...")
        success = await self._do_login()
        if success:
            self.is_logged_in = True
            print(f"✅ LinuxDoSession [{self.username_hash}]: Login successful")
        else:
            print(f"❌ LinuxDoSession [{self.username_hash}]: Login failed")

        return success

    async def _verify_cached_session(self) -> bool:
        """验证缓存的会话是否有效

        Returns:
            bool: 会话是否有效
        """
        try:
            async with AsyncCamoufox(
                headless=True,
                humanize=True,
                locale="en-US",
                geoip=True if self.proxy else False,
                proxy=self.proxy,
            ) as browser:
                context = await browser.new_context(storage_state=self.storage_state_path)
                page = await context.new_page()

                try:
                    # 访问 linux.do 检查登录状态
                    await page.goto("https://linux.do", wait_until="domcontentloaded")
                    # 等待页面稳定，使用较短的固定等待
                    await page.wait_for_timeout(1500)

                    # 检查是否有用户头像或登录按钮
                    # 如果有 .current-user 元素，说明已登录
                    current_user = await page.query_selector(".current-user")
                    if current_user:
                        print(f"✅ LinuxDoSession [{self.username_hash}]: Cache session is valid")
                        # 加载 storage state 到内存
                        self._storage_state = await context.storage_state()
                        return True

                    # 检查是否有登录按钮（说明未登录）
                    login_btn = await page.query_selector(".login-button")
                    if login_btn:
                        print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Cache session expired (login button found)")
                        return False

                    # 不确定状态，尝试访问 connect.linux.do 验证
                    await page.goto("https://connect.linux.do", wait_until="domcontentloaded")
                    await page.wait_for_timeout(1000)

                    # 如果被重定向到登录页，说明未登录
                    if "login" in page.url.lower():
                        return False

                    # 加载 storage state 到内存
                    self._storage_state = await context.storage_state()
                    return True

                except Exception as e:
                    print(f"⚠️ LinuxDoSession [{self.username_hash}]: Error verifying cache: {e}")
                    return False
                finally:
                    await page.close()
                    await context.close()

        except Exception as e:
            print(f"⚠️ LinuxDoSession [{self.username_hash}]: Error starting browser for verification: {e}")
            return False

    async def _do_login(self) -> bool:
        """执行 Linux.do 登录

        Returns:
            bool: 登录是否成功
        """
        try:
            async with AsyncCamoufox(
                headless=True,  # 登录时使用无头模式
                humanize=True,
                locale="en-US",
                geoip=True if self.proxy else False,
                proxy=self.proxy,
            ) as browser:
                context = await browser.new_context()
                page = await context.new_page()

                try:
                    print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Navigating to login page")
                    await page.goto("https://linux.do/login", wait_until="domcontentloaded")
                    await page.wait_for_timeout(1500)

                    # 填写登录表单
                    print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Filling credentials")
                    await page.fill("#login-account-name", self.username)
                    await page.wait_for_timeout(500)
                    await page.fill("#login-account-password", self.password)
                    await page.wait_for_timeout(500)

                    # 点击登录按钮
                    print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Clicking login button")
                    await page.click("#login-button")
                    # 等待登录完成：检测 URL 变化或用户元素出现
                    try:
                        await page.wait_for_selector(".current-user", timeout=15000)
                    except Exception:
                        # 如果超时，继续检查其他条件
                        await page.wait_for_timeout(3000)

                    # 检查登录结果
                    current_url = page.url
                    print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Current URL: {current_url}")

                    # 处理 Cloudflare 验证
                    if "linux.do/challenge" in current_url:
                        print(f"⚠️ LinuxDoSession [{self.username_hash}]: Cloudflare challenge detected, waiting...")
                        try:
                            await page.wait_for_url("https://linux.do/", timeout=60000)
                            print(f"✅ LinuxDoSession [{self.username_hash}]: Cloudflare challenge bypassed")
                        except Exception:
                            print(f"⚠️ LinuxDoSession [{self.username_hash}]: Cloudflare challenge timeout")

                    # 验证登录成功
                    await page.wait_for_timeout(1000)
                    current_user = await page.query_selector(".current-user")
                    if not current_user:
                        # 再等待一下
                        await page.wait_for_timeout(2000)
                        current_user = await page.query_selector(".current-user")

                    if current_user:
                        # 保存会话状态
                        await context.storage_state(path=self.storage_state_path)
                        self._storage_state = await context.storage_state()
                        print(f"✅ LinuxDoSession [{self.username_hash}]: Login successful, session saved")
                        return True
                    else:
                        # 检查是否在首页（可能已登录但没有 current-user 元素）
                        if "linux.do" in current_url and "login" not in current_url:
                            await context.storage_state(path=self.storage_state_path)
                            self._storage_state = await context.storage_state()
                            print(f"✅ LinuxDoSession [{self.username_hash}]: Login appears successful")
                            return True

                        print(f"❌ LinuxDoSession [{self.username_hash}]: Login failed - still on login page")
                        await take_screenshot(page, "linuxdo_login_failed", f"session_{self.username_hash}")
                        return False

                except Exception as e:
                    print(f"❌ LinuxDoSession [{self.username_hash}]: Login error: {e}")
                    await take_screenshot(page, "linuxdo_login_error", f"session_{self.username_hash}")
                    return False
                finally:
                    await page.close()
                    await context.close()

        except Exception as e:
            print(f"❌ LinuxDoSession [{self.username_hash}]: Browser error: {e}")
            return False

    def get_storage_state_path(self) -> str:
        """获取 storage state 文件路径

        Returns:
            str: 文件路径
        """
        return self.storage_state_path

    async def get_storage_state(self) -> dict | None:
        """获取当前会话的 storage state

        Returns:
            dict | None: storage state 字典，如果未登录则返回 None
        """
        if self._storage_state:
            return self._storage_state

        # 尝试从文件加载
        if os.path.exists(self.storage_state_path):
            try:
                with open(self.storage_state_path, "r") as f:
                    self._storage_state = json.load(f)
                return self._storage_state
            except Exception as e:
                print(f"⚠️ LinuxDoSession [{self.username_hash}]: Error loading storage state: {e}")

        return None

    def invalidate(self):
        """使会话失效，下次调用 ensure_logged_in 时会重新登录"""
        self.is_logged_in = False
        self._storage_state = None
        print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Session invalidated")


class LinuxDoSessionManager:
    """Linux.do 会话管理器 - 单例模式"""

    _sessions: dict[str, LinuxDoSession] = {}

    @classmethod
    async def get_session(
        cls,
        username: str,
        password: str,
        proxy: dict | None = None,
        auto_login: bool = True,
    ) -> LinuxDoSession:
        """获取或创建 Linux.do 会话

        Args:
            username: Linux.do 用户名
            password: Linux.do 密码
            proxy: 代理配置
            auto_login: 是否自动执行登录（默认 True）

        Returns:
            LinuxDoSession: 会话对象
        """
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]

        # 检查是否已有会话
        if username_hash in cls._sessions:
            session = cls._sessions[username_hash]
            print(f"ℹ️ LinuxDoSessionManager: Reusing existing session for [{username_hash}]")
            if auto_login:
                await session.ensure_logged_in()
            return session

        # 创建新会话
        print(f"ℹ️ LinuxDoSessionManager: Creating new session for [{username_hash}]")
        session = LinuxDoSession(username, password, proxy)
        cls._sessions[username_hash] = session

        if auto_login:
            await session.ensure_logged_in()

        return session

    @classmethod
    def get_cached_session(cls, username: str) -> LinuxDoSession | None:
        """获取已缓存的会话（不创建新会话）

        Args:
            username: Linux.do 用户名

        Returns:
            LinuxDoSession | None: 会话对象，如果不存在则返回 None
        """
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        return cls._sessions.get(username_hash)

    @classmethod
    def clear_session(cls, username: str):
        """清除指定用户的会话缓存

        Args:
            username: Linux.do 用户名
        """
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        if username_hash in cls._sessions:
            cls._sessions[username_hash].invalidate()
            del cls._sessions[username_hash]
            print(f"ℹ️ LinuxDoSessionManager: Session [{username_hash}] cleared")

    @classmethod
    def clear_all_sessions(cls):
        """清除所有会话缓存"""
        for session in cls._sessions.values():
            session.invalidate()
        cls._sessions.clear()
        print("ℹ️ LinuxDoSessionManager: All sessions cleared")

    @classmethod
    def get_session_count(cls) -> int:
        """获取当前缓存的会话数量"""
        return len(cls._sessions)
