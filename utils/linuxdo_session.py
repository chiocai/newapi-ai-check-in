#!/usr/bin/env python3
"""
Linux.do 会话管理器

实现 Linux.do 登录会话的共享和复用，避免同一账号重复登录
"""

import hashlib
import json
import os
import time
from typing import TYPE_CHECKING

from camoufox.async_api import AsyncCamoufox

from utils.browser_utils import (
    attempt_linuxdo_human_verification,
    detect_linuxdo_page_guard,
    has_linuxdo_human_verification,
    save_page_content_to_file,
    take_screenshot,
    wait_for_linuxdo_login_ready,
)

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
            self.invalidate()
            print(f"❌ LinuxDoSession [{self.username_hash}]: Cache invalid, manual warm-up is required")
            return False

        print(f"❌ LinuxDoSession [{self.username_hash}]: No prewarmed cache file found")
        self.invalidate()
        return False

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

                    current_url = page.url.lower()
                    if "linux.do/login" in current_url:
                        return False

                    # 预热模式下只要主页没有回到登录页，也没有出现登录按钮，就优先信任这份缓存。
                    # 真实是否可用于 OAuth 交给后续站点授权流程判断，避免在预检阶段误杀可用会话。
                    print(
                        f"✅ LinuxDoSession [{self.username_hash}]: Cache session looks reusable from linux.do homepage"
                    )
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
                    try:
                        await wait_for_linuxdo_login_ready(page, f"session_{self.username_hash}")
                    except Exception as ready_err:
                        guard = await detect_linuxdo_page_guard(page)
                        print(f"⚠️ LinuxDoSession [{self.username_hash}]: Login form not ready: {ready_err}")
                        if guard.get("human_verification"):
                            await save_page_content_to_file(
                                page,
                                "linuxdo_hcaptcha_before_login_ready",
                                f"session_{self.username_hash}",
                            )
                            await take_screenshot(page, "linuxdo_hcaptcha_before_login_ready", f"session_{self.username_hash}")
                            return False
                        if guard.get("cloudflare_challenge"):
                            await save_page_content_to_file(
                                page,
                                "linuxdo_cloudflare_before_login_ready",
                                f"session_{self.username_hash}",
                            )
                            await take_screenshot(page, "linuxdo_cloudflare_before_login_ready", f"session_{self.username_hash}")
                            return False
                        raise

                    # 填写登录表单
                    print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Filling credentials")
                    await page.fill("#login-account-name", self.username)
                    await page.wait_for_timeout(500)
                    await page.fill("#login-account-password", self.password)
                    await page.wait_for_timeout(500)

                    if await has_linuxdo_human_verification(page):
                        solved = await attempt_linuxdo_human_verification(page, f"session_{self.username_hash}")
                        if not solved:
                            guard = await detect_linuxdo_page_guard(page)
                            print(f"❌ LinuxDoSession [{self.username_hash}]: Human Verification (hCaptcha) detected")
                            await save_page_content_to_file(page, "linuxdo_hcaptcha_detected", f"session_{self.username_hash}")
                            await take_screenshot(page, "linuxdo_hcaptcha_detected", f"session_{self.username_hash}")
                            if guard.get("human_verification_sitekey"):
                                print(
                                    f"⚠️ LinuxDoSession [{self.username_hash}]: "
                                    f"hCaptcha sitekey={guard['human_verification_sitekey']}"
                                )
                            return False

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

                    current_url = page.url
                    post_login_guard = await detect_linuxdo_page_guard(page)
                    if "linux.do/login" in current_url and post_login_guard.get("human_verification"):
                        solved = await attempt_linuxdo_human_verification(page, f"session_{self.username_hash}")
                        if solved:
                            print(
                                f"ℹ️ LinuxDoSession [{self.username_hash}]: "
                                "Human Verification solved after submit, retrying login once"
                            )
                            await page.click("#login-button")
                            await page.wait_for_timeout(5000)
                            current_url = page.url
                            post_login_guard = await detect_linuxdo_page_guard(page)

                        if "linux.do/login" in current_url and post_login_guard.get("human_verification"):
                            print(f"❌ LinuxDoSession [{self.username_hash}]: Human Verification still blocks session after submit")
                            await save_page_content_to_file(
                                page, "linuxdo_hcaptcha_after_login_click", f"session_{self.username_hash}"
                            )
                            await take_screenshot(page, "linuxdo_hcaptcha_after_login_click", f"session_{self.username_hash}")
                            if post_login_guard.get("human_verification_sitekey"):
                                print(
                                    f"⚠️ LinuxDoSession [{self.username_hash}]: "
                                    f"hCaptcha sitekey={post_login_guard['human_verification_sitekey']}"
                                )
                            return False

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
        if not self.is_logged_in:
            return None

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

    async def prepare_manually(self, timeout_seconds: int = 600) -> bool:
        """手工预热 Linux.do 登录会话"""
        deadline = time.time() + timeout_seconds
        try:
            async with AsyncCamoufox(
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.proxy else False,
                proxy=self.proxy,
            ) as browser:
                storage_state = self.storage_state_path if os.path.exists(self.storage_state_path) else None
                context = await browser.new_context(storage_state=storage_state)
                page = await context.new_page()

                try:
                    print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Opening visible browser for manual warm-up")
                    await page.goto("https://linux.do/login", wait_until="domcontentloaded")

                    try:
                        await wait_for_linuxdo_login_ready(page, f"session_{self.username_hash}")
                        await page.fill("#login-account-name", self.username)
                        await page.fill("#login-account-password", self.password)
                        print(f"ℹ️ LinuxDoSession [{self.username_hash}]: Credentials pre-filled, please complete login manually")
                    except Exception as exc:
                        print(f"⚠️ LinuxDoSession [{self.username_hash}]: Unable to pre-fill login form: {exc}")

                    while time.time() < deadline:
                        current_url = page.url
                        current_user = await page.query_selector(".current-user")
                        guard = await detect_linuxdo_page_guard(page)

                        if current_user or ("linux.do/login" not in current_url and not guard.get("human_verification")):
                            await context.storage_state(path=self.storage_state_path)
                            self._storage_state = await context.storage_state()
                            self.is_logged_in = True
                            print(f"✅ LinuxDoSession [{self.username_hash}]: Manual warm-up successful, session saved")
                            return True

                        await page.wait_for_timeout(2000)

                    print(f"❌ LinuxDoSession [{self.username_hash}]: Manual warm-up timeout")
                    await save_page_content_to_file(page, "linuxdo_manual_warmup_timeout", f"session_{self.username_hash}")
                    await take_screenshot(page, "linuxdo_manual_warmup_timeout", f"session_{self.username_hash}")
                    return False
                finally:
                    await page.close()
                    await context.close()
        except Exception as exc:
            print(f"❌ LinuxDoSession [{self.username_hash}]: Manual warm-up error: {exc}")
            return False


class LinuxDoSessionManager:
    """Linux.do 会话管理器 - 单例模式"""

    _sessions: dict[str, LinuxDoSession] = {}
    _circuit_breakers: dict[str, str] = {}

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
        circuit_reason = cls._circuit_breakers.get(username_hash)

        # 检查是否已有会话
        if username_hash in cls._sessions:
            session = cls._sessions[username_hash]
            print(f"ℹ️ LinuxDoSessionManager: Reusing existing session for [{username_hash}]")
            if auto_login and not circuit_reason:
                await session.ensure_logged_in()
            elif auto_login and circuit_reason:
                print(f"⚠️ LinuxDoSessionManager: Session [{username_hash}] circuit is open, skip auto-login: {circuit_reason}")
            return session

        # 创建新会话
        print(f"ℹ️ LinuxDoSessionManager: Creating new session for [{username_hash}]")
        session = LinuxDoSession(username, password, proxy)
        cls._sessions[username_hash] = session

        if auto_login and not circuit_reason:
            await session.ensure_logged_in()
        elif auto_login and circuit_reason:
            print(f"⚠️ LinuxDoSessionManager: Session [{username_hash}] circuit is open, skip auto-login: {circuit_reason}")

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
    def trip_circuit(cls, username: str, reason: str):
        """对指定 Linux.do 用户名开启本轮熔断，避免继续打 OAuth"""
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        cls._circuit_breakers[username_hash] = reason
        if username_hash in cls._sessions:
            cls._sessions[username_hash].invalidate()
        print(f"⚠️ LinuxDoSessionManager: Circuit opened for [{username_hash}] - {reason}")

    @classmethod
    def get_circuit_reason(cls, username: str) -> str | None:
        """获取指定 Linux.do 用户名的熔断原因"""
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        return cls._circuit_breakers.get(username_hash)

    @classmethod
    def clear_circuit(cls, username: str):
        """清除指定 Linux.do 用户名的熔断状态"""
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        if username_hash in cls._circuit_breakers:
            del cls._circuit_breakers[username_hash]
            print(f"ℹ️ LinuxDoSessionManager: Circuit cleared for [{username_hash}]")

    @classmethod
    def clear_all_circuits(cls):
        """清除所有 Linux.do 熔断状态"""
        cls._circuit_breakers.clear()
        print("ℹ️ LinuxDoSessionManager: All circuits cleared")

    @classmethod
    def get_session_count(cls) -> int:
        """获取当前缓存的会话数量"""
        return len(cls._sessions)
