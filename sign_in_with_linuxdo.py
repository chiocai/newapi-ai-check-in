#!/usr/bin/env python3
"""
使用 Camoufox 绕过 Cloudflare 验证执行 Linux.do 签到
"""

import asyncio
import json
import os
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from camoufox.async_api import AsyncCamoufox

from utils.browser_utils import (
    attempt_linuxdo_human_verification,
    detect_linuxdo_page_guard,
    filter_cookies,
    has_linuxdo_human_verification,
    save_page_content_to_file,
    take_screenshot,
    wait_for_linuxdo_login_ready,
)
from utils.config import ProviderConfig

if TYPE_CHECKING:
    from utils.linuxdo_session import LinuxDoSession

# 超时配置（毫秒）
TIMEOUT_PAGE_LOAD = 60000  # 页面加载超时
TIMEOUT_ELEMENT_WAIT = 45000  # 元素等待超时
TIMEOUT_CLOUDFLARE = 90000  # Cloudflare 验证超时
TIMEOUT_FILL = 30000  # 填写表单超时
TIMEOUT_CLICK = 30000  # 点击超时
TIMEOUT_NAVIGATION = 45000  # 导航超时

# 重试配置
MAX_RETRIES = 3  # 最大重试次数
RETRY_DELAY = 3  # 重试间隔（秒）
MAX_CONCURRENT_LINUXDO_OAUTH = max(
    1,
    int(os.getenv("MAX_CONCURRENT_LINUXDO_OAUTH", "1"))
)  # Linux.do OAuth 浏览器流程最大并发数

_linuxdo_signin_semaphore: asyncio.Semaphore | None = None


def get_linuxdo_signin_semaphore() -> asyncio.Semaphore:
    """延迟初始化 Linux.do OAuth 并发控制信号量"""
    global _linuxdo_signin_semaphore
    if _linuxdo_signin_semaphore is None:
        _linuxdo_signin_semaphore = asyncio.Semaphore(MAX_CONCURRENT_LINUXDO_OAUTH)
    return _linuxdo_signin_semaphore


def _build_linuxdo_error(error_type: str, error_summary: str, error_detail: str | None = None, **extra) -> dict:
    """构造结构化 Linux.do 错误信息"""
    payload = {
        'error_type': error_type,
        'error_summary': error_summary,
        'error_detail': error_detail or error_summary,
        'error': error_detail or error_summary,
    }
    for key, value in extra.items():
        if value is not None:
            payload[key] = value
    return payload


async def _diagnose_linuxdo_page_issue(page) -> dict | None:
    """根据当前页面状态诊断 Linux.do 失败原因"""
    guard = await detect_linuxdo_page_guard(page)
    current_url = page.url
    current_url_lower = current_url.lower()
    sitekey = guard.get('human_verification_sitekey')
    suffix = f', sitekey={sitekey}' if sitekey else ''

    if guard.get('human_verification'):
        if 'linux.do/login' in current_url_lower:
            return _build_linuxdo_error(
                'linuxdo_hcaptcha_login',
                'Linux.do 登录页人机验证(hCaptcha)',
                f'Linux.do login is blocked by Human Verification at {current_url}{suffix}',
                sitekey=sitekey,
            )
        return _build_linuxdo_error(
            'linuxdo_hcaptcha_authorize',
            'Linux.do 授权页人机验证(hCaptcha)',
            f'Linux.do authorization is blocked by Human Verification at {current_url}{suffix}',
            sitekey=sitekey,
        )

    if guard.get('cloudflare_challenge'):
        return _build_linuxdo_error(
            'linuxdo_cloudflare_challenge',
            'Linux.do Cloudflare 挑战页',
            f'Linux.do Cloudflare challenge is blocking the flow at {current_url}',
        )

    # URL 级别状态优先于正文关键字，避免 sso_provider/login 页面被误报为高负载
    if 'linux.do/session/sso_provider' in current_url_lower:
        return _build_linuxdo_error(
            'linuxdo_sso_provider_stuck',
            'Linux.do SSO 中转页卡住',
            f'Linux.do SSO provider page is stuck at {current_url}',
        )

    if 'linux.do/login' in current_url_lower:
        return _build_linuxdo_error(
            'linuxdo_redirect_login',
            'Linux.do 会话失效，被重定向回登录页',
            f'Linux.do authorization redirected back to login page: {current_url}',
        )

    if guard.get('high_load'):
        return _build_linuxdo_error(
            'linuxdo_high_load',
            'Linux.do 授权页高负载，请稍后重试',
            f'Linux.do authorization page is under high load at {current_url}',
        )

    return None


class LinuxDoSignIn:
    """使用 Linux.do 登录授权类"""

    def __init__(
        self,
        account_name: str,
        provider_config: ProviderConfig,
        username: str,
        password: str,
        shared_session: "LinuxDoSession | None" = None,
    ):
        """初始化

        Args:
            account_name: 账号名称
            provider_config: 提供商配置
            username: Linux.do 用户名
            password: Linux.do 密码
            shared_session: 共享的 Linux.do 会话（可选）
        """
        self.account_name = account_name
        self.provider_config = provider_config
        self.username = username
        self.password = password
        self.shared_session = shared_session

    async def signin(
        self,
        client_id: str,
        auth_state: str,
        auth_cookies: list,
        cache_file_path: str = '',
    ) -> tuple[bool, dict]:
        """使用 Linux.do 账号执行登录授权（带重试机制）

        Args:
            client_id: OAuth 客户端 ID
            auth_state: OAuth 认证状态
            auth_cookies: OAuth 认证 cookies
            cache_file_path: 缓存文件

        Returns:
            (成功标志, 用户信息字典)
        """
        last_error = None
        last_error_summary = None
        last_result_payload = None
        pending_force_fresh_login = False
        fresh_login_retry_used = False
        recoverable_session_error_types = {
            'linuxdo_sso_provider_stuck',
            'linuxdo_redirect_login',
        }
        has_cached_state_hint = bool(self.shared_session) or bool(cache_file_path and os.path.exists(cache_file_path))

        for attempt in range(1, MAX_RETRIES + 1):
            force_fresh_login = pending_force_fresh_login
            pending_force_fresh_login = False
            try:
                if attempt > 1:
                    if force_fresh_login:
                        print(f"ℹ️ {self.account_name}: Retrying once with fresh Linux.do login")
                    else:
                        print(f"ℹ️ {self.account_name}: Retry attempt {attempt}/{MAX_RETRIES}")
                        await asyncio.sleep(RETRY_DELAY)

                async with get_linuxdo_signin_semaphore():
                    result = await self._signin_impl(
                        client_id,
                        auth_state,
                        auth_cookies,
                        cache_file_path,
                        force_fresh_login=force_fresh_login,
                    )
                if result[0]:
                    return result

                last_result_payload = result[1] or {}
                last_error = last_result_payload.get('error', 'Unknown error')
                last_error_summary = last_result_payload.get('error_summary', last_error)
                error_type = last_result_payload.get('error_type')

                if (
                    not force_fresh_login
                    and not fresh_login_retry_used
                    and has_cached_state_hint
                    and error_type in recoverable_session_error_types
                ):
                    fresh_login_retry_used = True
                    pending_force_fresh_login = True
                    print(
                        f"⚠️ {self.account_name}: Cached Linux.do session failed with {error_type}, "
                        "retrying once with fresh login"
                    )
                    if self.shared_session:
                        self.shared_session.invalidate()
                    continue

                non_retry_error_types = {
                    'linuxdo_hcaptcha_login',
                    'linuxdo_hcaptcha_authorize',
                    'linuxdo_cloudflare_challenge',
                    'linuxdo_high_load',
                    *recoverable_session_error_types,
                }
                non_retry_keywords = [
                    'not found',
                    'human verification',
                    'hcaptcha',
                    'h-captcha',
                    'cloudflare challenge',
                    'high load',
                    'sso provider page is stuck',
                    'redirected back to login page',
                ]
                if error_type in non_retry_error_types or any(
                    keyword in str(last_error).lower() for keyword in non_retry_keywords
                ):
                    print(f"❌ {self.account_name}: Non-retryable error: {last_error_summary}")
                    return result
                print(f"⚠️ {self.account_name}: Attempt {attempt} failed: {last_error_summary}")

            except Exception as e:
                last_error = str(e)
                last_error_summary = last_error
                print(f"⚠️ {self.account_name}: Attempt {attempt} exception: {e}")

        print(f"❌ {self.account_name}: All {MAX_RETRIES} attempts failed. Last error: {last_error}")
        payload = dict(last_result_payload or {})
        payload["error"] = f"All {MAX_RETRIES} attempts failed: {last_error}"
        payload.setdefault("error_summary", last_error_summary or last_error)
        payload.setdefault("error_detail", last_error)
        payload.setdefault("error_type", "linuxdo_signin_failed")
        return False, payload

    async def _handle_sso_provider_page(self, page) -> str:
        """处理 linux.do/session/sso_provider 中转页"""
        print(f"ℹ️ {self.account_name}: Linux.do SSO provider page detected, waiting for redirect...")

        try:
            await page.wait_for_url("**connect.linux.do/**", timeout=12000)
            return page.url
        except Exception:
            pass

        try:
            await page.wait_for_url(f"**{self.provider_config.origin.replace('https://', '').replace('http://', '')}/**", timeout=5000)
            return page.url
        except Exception:
            pass

        current_url = page.url
        if "linux.do/session/sso_provider" not in current_url:
            return current_url

        print(f"⚠️ {self.account_name}: sso_provider did not auto-redirect, trying generic submit/click handlers")
        handled = await page.evaluate("""() => {
            const textMatches = (el) => {
                const text = (el.innerText || el.textContent || el.value || '').trim();
                return /允许|继续|authorize|continue|approve|sign in|login/i.test(text);
            };

            const clickable = Array.from(document.querySelectorAll('button, a, input[type="submit"], input[type="button"]'))
                .find((el) => textMatches(el));
            if (clickable) {
                clickable.click();
                return 'clicked:' + (clickable.innerText || clickable.value || clickable.tagName);
            }

            const form = document.querySelector('form');
            if (form) {
                form.submit();
                return 'submitted:form';
            }

            return 'noop';
        }""")
        print(f"ℹ️ {self.account_name}: Linux.do sso_provider handler result: {handled}")

        if handled == "noop":
            try:
                post_result = await page.evaluate("""async () => {
                    const form = document.querySelector('form');
                    if (!form) return 'no-form';
                    const action = form.action || window.location.href;
                    const data = new FormData(form);
                    const body = new URLSearchParams(data).toString();
                    const resp = await fetch(action, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: body,
                        redirect: 'follow',
                    });
                    return 'fetch:' + resp.status + ':' + resp.url;
                }""")
                print(f"ℹ️ {self.account_name}: Linux.do sso_provider fetch POST result: {post_result}")
            except Exception as fetch_err:
                print(f"⚠️ {self.account_name}: Linux.do sso_provider fetch POST failed: {fetch_err}")

        try:
            await page.wait_for_url("**connect.linux.do/**", timeout=12000)
        except Exception:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(self.provider_config.origin)
                await page.wait_for_url(f"**{parsed.netloc}/**", timeout=TIMEOUT_NAVIGATION)
            except Exception:
                await page.wait_for_timeout(2000)

        current_url = page.url
        print(f"ℹ️ {self.account_name}: URL after Linux.do sso_provider handler: {current_url}")
        if "linux.do/session/sso_provider" in current_url:
            await save_page_content_to_file(page, "linuxdo_sso_provider_stuck", self.account_name, prefix="linuxdo")
            await take_screenshot(page, "linuxdo_sso_provider_stuck", self.account_name)
        return current_url

    async def _resolve_storage_state(self, cache_file_path: str = '', force_fresh_login: bool = False):
        """解析当前登录流程应使用的 storage state"""
        storage_state = None
        if force_fresh_login:
            print(f"ℹ️ {self.account_name}: Force fresh Linux.do login, skipping cached storage state")
            return None

        skip_cache_file = False
        if self.shared_session:
            if getattr(self.shared_session, 'is_logged_in', False):
                shared_state = await self.shared_session.get_storage_state()
                if shared_state:
                    print(f"ℹ️ {self.account_name}: Using shared session storage state from memory")
                    return shared_state

                shared_state_path = self.shared_session.get_storage_state_path()
                if os.path.exists(shared_state_path):
                    print(f"ℹ️ {self.account_name}: Using shared session storage state from file")
                    return shared_state_path
            else:
                skip_cache_file = True
                print(
                    f"ℹ️ {self.account_name}: Shared Linux.do session is not logged in for this run, "
                    "skip cached storage state"
                )

        if not skip_cache_file and cache_file_path and os.path.exists(cache_file_path):
            print(f"ℹ️ {self.account_name}: Found cache file, restore storage state")
            return cache_file_path

        return storage_state

    async def _signin_impl(
        self,
        client_id: str,
        auth_state: str,
        auth_cookies: list,
        cache_file_path: str = "",
        force_fresh_login: bool = False,
    ) -> tuple[bool, dict]:
        """实际的登录实现"""
        print(f"ℹ️ {self.account_name}: Executing sign-in with Linux.do")
        print(
            f"ℹ️ {self.account_name}: Using client_id: {client_id}, auth_state: {auth_state}, cache_file: {cache_file_path}"
        )

        # 确定 storage_state 来源：优先使用共享会话
        storage_state = await self._resolve_storage_state(cache_file_path, force_fresh_login=force_fresh_login)

        if not storage_state:
            print(f"ℹ️ {self.account_name}: No cache file found, starting fresh")

        # 使用 Camoufox 启动浏览器
        async with AsyncCamoufox(
            # persistent_context=True,
            # user_data_dir=tmp_dir,
            headless=True,
            humanize=True,
            locale="en-US",
        ) as browser:

            context = await browser.new_context(storage_state=storage_state)

            # 设置从参数获取的 auth cookies 到页面上下文
            if auth_cookies:
                await context.add_cookies(auth_cookies)
                print(f"ℹ️ {self.account_name}: Set {len(auth_cookies)} auth cookies from provider")
            else:
                print(f"ℹ️ {self.account_name}: No auth cookies to set")

            page = await context.new_page()

            try:
                # 检查是否已经登录（通过缓存恢复）
                is_logged_in = False
                oauth_url = (
                    f"https://connect.linux.do/oauth2/authorize?"
                    f"response_type=code&client_id={client_id}&state={auth_state}"
                )

                if storage_state:
                    try:
                        print(f"ℹ️ {self.account_name}: Checking login status at {oauth_url}")
                        # 直接访问授权页面检查是否已登录
                        try:
                            response = await page.goto(oauth_url, wait_until="networkidle", timeout=TIMEOUT_PAGE_LOAD)
                        except Exception:
                            response = await page.goto(oauth_url, wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                            await page.wait_for_timeout(3000)
                        print(f"ℹ️ {self.account_name}: redirected to app page {response.url if response else 'N/A'}")

                        # 检查是否遇到 Cloudflare 挑战页面
                        page_title = await page.title()
                        if "Just a moment" in page_title or "challenge" in page.url.lower():
                            print(
                                f"⚠️ {self.account_name}: Cloudflare challenge detected on OAuth page, "
                                "waiting for challenge to complete..."
                            )
                            try:
                                # 等待 Cloudflare 挑战完成（页面标题变化或授权按钮出现）
                                await page.wait_for_function(
                                    "document.title !== 'Just a moment...'",
                                    timeout=TIMEOUT_CLOUDFLARE
                                )
                                await page.wait_for_timeout(1500)  # 额外等待页面稳定
                                print(f"✅ {self.account_name}: Cloudflare challenge completed")
                            except Exception as cf_err:
                                print(f"⚠️ {self.account_name}: Cloudflare challenge timeout: {cf_err}")

                        await save_page_content_to_file(page, "sign_in_check", self.account_name, prefix="linuxdo")

                        current_url = page.url
                        if "linux.do/session/sso_provider" in current_url:
                            current_url = await self._handle_sso_provider_page(page)

                        # 登录后可能直接跳转回应用页面
                        if response and response.url.startswith(self.provider_config.origin):
                            is_logged_in = True
                            print(f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization")
                        elif current_url.startswith(self.provider_config.origin):
                            is_logged_in = True
                            print(f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization")
                        else:
                            # 检查是否出现授权按钮（表示已登录）
                            allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                            if allow_btn:
                                is_logged_in = True
                                print(
                                    f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
                                )
                            else:
                                if "linux.do/session/sso_provider" in current_url:
                                    print(f"❌ {self.account_name}: Cache session stalled at Linux.do SSO provider page")
                                    diagnosed = await _diagnose_linuxdo_page_issue(page)
                                    if diagnosed:
                                        return False, diagnosed
                                    return False, _build_linuxdo_error(
                                        "linuxdo_sso_provider_stuck",
                                        "Linux.do SSO 中转页卡住",
                                        f"Linux.do SSO provider page is stuck after cache restore: {current_url}",
                                    )
                                elif "connect.linux.do" in current_url:
                                    print(
                                        f"⚠️ {self.account_name}: Cache session reached connect.linux.do but approve button is missing, "
                                        "fallback to fresh Linux.do login"
                                    )
                                else:
                                    print(f"ℹ️ {self.account_name}: Cache session expired, need to login again")
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Failed to check login status: {e}")

                # 如果未登录，则执行登录流程
                if not is_logged_in:
                    try:
                        print(f"ℹ️ {self.account_name}: Starting to sign in linux.do")

                        await page.goto("https://linux.do/login", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)

                        try:
                            await wait_for_linuxdo_login_ready(page, self.account_name, timeout=TIMEOUT_ELEMENT_WAIT)
                        except Exception as ready_err:
                            guard = await detect_linuxdo_page_guard(page)
                            print(f"⚠️ {self.account_name}: Login form not ready: {ready_err}")
                            if guard.get("human_verification"):
                                await save_page_content_to_file(page, "linuxdo_hcaptcha_before_login_ready", self.account_name, prefix="linuxdo")
                                await take_screenshot(page, "linuxdo_hcaptcha_before_login_ready", self.account_name)
                                sitekey = guard.get("human_verification_sitekey")
                                suffix = f", sitekey={sitekey}" if sitekey else ""
                                return False, _build_linuxdo_error(
                                    "linuxdo_hcaptcha_login",
                                    "Linux.do 登录前需要人机验证(hCaptcha)",
                                    f"LinuxDo login blocked by Human Verification before form ready{suffix}",
                                    sitekey=sitekey,
                                )
                            if guard.get("cloudflare_challenge"):
                                await save_page_content_to_file(page, "linuxdo_cloudflare_before_login_ready", self.account_name, prefix="linuxdo")
                                await take_screenshot(page, "linuxdo_cloudflare_before_login_ready", self.account_name)
                                return False, _build_linuxdo_error(
                                    "linuxdo_cloudflare_challenge",
                                    "Linux.do 登录前被 Cloudflare 挑战页拦截",
                                    "LinuxDo login blocked by Cloudflare challenge before form ready",
                                )
                            await page.wait_for_timeout(2000)
                            await wait_for_linuxdo_login_ready(page, self.account_name, timeout=TIMEOUT_ELEMENT_WAIT)

                        await page.fill("#login-account-name", self.username, timeout=TIMEOUT_FILL)
                        await page.wait_for_timeout(500)
                        await page.fill("#login-account-password", self.password, timeout=TIMEOUT_FILL)
                        await page.wait_for_timeout(500)

                        if await has_linuxdo_human_verification(page):
                            solved = await attempt_linuxdo_human_verification(page, self.account_name)
                            if not solved:
                                guard = await detect_linuxdo_page_guard(page)
                                await save_page_content_to_file(page, "linuxdo_hcaptcha_detected", self.account_name, prefix="linuxdo")
                                await take_screenshot(page, "linuxdo_hcaptcha_detected", self.account_name)
                                sitekey = guard.get("human_verification_sitekey")
                                suffix = f", sitekey={sitekey}" if sitekey else ""
                                return False, _build_linuxdo_error(
                                    "linuxdo_hcaptcha_login",
                                    "Linux.do 登录前需要人机验证(hCaptcha)",
                                    (
                                        f"LinuxDo login requires Human Verification (hCaptcha){suffix}. "
                                        "Please warm up LinuxDo session manually with `uv run python prepare_linuxdo_session.py`"
                                    ),
                                    sitekey=sitekey,
                                )

                        await page.click("#login-button", timeout=TIMEOUT_CLICK)
                        # 等待登录完成：检测用户元素出现或 URL 变化
                        try:
                            await page.wait_for_selector(".current-user", timeout=15000)
                        except Exception:
                            await page.wait_for_timeout(3000)

                        await save_page_content_to_file(page, "sign_in_result", self.account_name, prefix="linuxdo")

                        try:
                            current_url = page.url
                            print(f"ℹ️ {self.account_name}: Current page url is {current_url}")
                            if "linux.do/challenge" in current_url:
                                print(
                                    f"⚠️ {self.account_name}: Cloudflare challenge detected, "
                                    "Camoufox should bypass it automatically. Waiting..."
                                )
                                # 等待 Cloudflare 验证完成
                                await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=TIMEOUT_CLOUDFLARE)
                                print(f"✅ {self.account_name}: Cloudflare challenge bypassed successfully")

                        except Exception as e:
                            print(f"⚠️ {self.account_name}: Possible Cloudflare challenge: {e}")
                            # 即使超时，也尝试继续
                            pass

                        post_login_guard = await detect_linuxdo_page_guard(page)
                        if "linux.do/login" in page.url and post_login_guard.get("human_verification"):
                            solved = await attempt_linuxdo_human_verification(page, self.account_name)
                            if solved:
                                print(f"ℹ️ {self.account_name}: Human Verification solved after login submit, retrying login once")
                                await page.click("#login-button", timeout=TIMEOUT_CLICK)
                                await page.wait_for_timeout(5000)
                                post_login_guard = await detect_linuxdo_page_guard(page)

                            if "linux.do/login" in page.url and post_login_guard.get("human_verification"):
                                await save_page_content_to_file(
                                    page, "linuxdo_hcaptcha_after_login_click", self.account_name, prefix="linuxdo"
                                )
                                await take_screenshot(page, "linuxdo_hcaptcha_after_login_click", self.account_name)
                                sitekey = post_login_guard.get("human_verification_sitekey")
                                suffix = f", sitekey={sitekey}" if sitekey else ""
                                return False, _build_linuxdo_error(
                                    "linuxdo_hcaptcha_login",
                                    "Linux.do 提交登录后仍需人机验证(hCaptcha)",
                                    (
                                        f"LinuxDo login still requires Human Verification after submit{suffix}. "
                                        "Please warm up LinuxDo session manually with `uv run python prepare_linuxdo_session.py`"
                                    ),
                                    sitekey=sitekey,
                                )

                        current_url = page.url
                        current_user = await page.query_selector(".current-user")
                        if current_user or "linux.do/login" not in current_url:
                            await context.storage_state(path=cache_file_path)
                            print(f"✅ {self.account_name}: Storage state saved to cache file")
                        else:
                            print(f"⚠️ {self.account_name}: Login not confirmed, skip overwriting LinuxDo cache file")

                    except Exception as e:
                        print(f"❌ {self.account_name}: Error occurred while signing in linux.do: {e}")
                        await take_screenshot(page, "signin_bypass_error", self.account_name)
                        diagnosed = await _diagnose_linuxdo_page_issue(page)
                        if diagnosed:
                            diagnosed["error_detail"] = f"{diagnosed['error_detail']}; original exception: {e}"
                            diagnosed["error"] = diagnosed["error_detail"]
                            return False, diagnosed
                        return False, _build_linuxdo_error(
                            "linuxdo_signin_error",
                            "Linux.do 登录流程异常",
                            f"Linux.do sign-in error: {e}",
                        )

                    # 登录后访问授权页面
                    try:
                        print(f"ℹ️ {self.account_name}: Navigating to authorization page: {oauth_url}")
                        try:
                            await page.goto(oauth_url, wait_until="networkidle", timeout=TIMEOUT_PAGE_LOAD)
                        except Exception:
                            await page.goto(oauth_url, wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                            await page.wait_for_timeout(3000)
                    except Exception as e:
                        print(f"❌ {self.account_name}: Failed to navigate to authorization page: {e}")
                        await take_screenshot(page, "auth_page_navigation_failed_bypass", self.account_name)
                        diagnosed = await _diagnose_linuxdo_page_issue(page)
                        if diagnosed:
                            diagnosed["error_detail"] = f"{diagnosed['error_detail']}; navigate exception: {e}"
                            diagnosed["error"] = diagnosed["error_detail"]
                            return False, diagnosed
                        return False, _build_linuxdo_error(
                            "linuxdo_authorization_navigation_failed",
                            "Linux.do 授权页打开失败",
                            f"Linux.do authorization page navigation failed: {e}",
                        )

                # 统一处理授权逻辑（无论是否通过缓存登录）
                try:
                    if "linux.do/session/sso_provider" in page.url:
                        current_url = await self._handle_sso_provider_page(page)
                        if "linux.do/session/sso_provider" in current_url:
                            diagnosed = await _diagnose_linuxdo_page_issue(page)
                            if diagnosed:
                                return False, diagnosed
                            return False, _build_linuxdo_error(
                                "linuxdo_sso_provider_stuck",
                                "Linux.do SSO 中转页卡住",
                                f"Linux.do SSO provider page is still stuck after handler: {current_url}",
                            )

                    if "linux.do/login" in page.url:
                        guard = await detect_linuxdo_page_guard(page)
                        if guard.get("human_verification"):
                            solved = await attempt_linuxdo_human_verification(page, self.account_name)
                            if not solved:
                                print(f"❌ {self.account_name}: Redirected back to LinuxDo login with Human Verification")
                                await save_page_content_to_file(
                                    page, "linuxdo_authorize_hcaptcha", self.account_name, prefix="linuxdo"
                                )
                                await take_screenshot(page, "linuxdo_authorize_hcaptcha", self.account_name)
                                sitekey = guard.get("human_verification_sitekey")
                                suffix = f", sitekey={sitekey}" if sitekey else ""
                                return False, _build_linuxdo_error(
                                    "linuxdo_hcaptcha_authorize",
                                    "Linux.do 授权页人机验证(hCaptcha)",
                                    f"LinuxDo authorization blocked by Human Verification (hCaptcha){suffix}",
                                    sitekey=sitekey,
                                )

                        print(f"❌ {self.account_name}: Redirected back to LinuxDo login page before authorization")
                        await save_page_content_to_file(page, "linuxdo_authorize_redirect_login", self.account_name, prefix="linuxdo")
                        await take_screenshot(page, "linuxdo_authorize_redirect_login", self.account_name)
                        return False, _build_linuxdo_error(
                            "linuxdo_redirect_login",
                            "Linux.do 授权前被重定向回登录页",
                            (
                                "LinuxDo authorization redirected back to login page. "
                                "Please warm up LinuxDo session manually with `uv run python prepare_linuxdo_session.py`"
                            ),
                        )

                    # 等待授权按钮出现
                    print(f"ℹ️ {self.account_name}: Waiting for authorization button...")
                    await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=TIMEOUT_ELEMENT_WAIT)
                    allow_btn_ele = await page.query_selector('a[href^="/oauth2/approve"]')

                    if allow_btn_ele:
                        print(f"ℹ️ {self.account_name}: Clicking authorization button...")
                        await allow_btn_ele.click()
                        # 等待页面跳转到 provider 域名（支持 HTTP 和 HTTPS，不限制路径）
                        from urllib.parse import urlparse
                        parsed = urlparse(self.provider_config.origin)
                        try:
                            await page.wait_for_url(f"**{parsed.netloc}/**", timeout=TIMEOUT_NAVIGATION)
                        except Exception:
                            # 如果超时，检查当前页面是否已经在 provider 域名
                            current_url = page.url
                            if parsed.netloc in current_url:
                                print(f"ℹ️ {self.account_name}: Already on provider domain: {current_url}")
                            else:
                                raise

                        # 从 localStorage 获取 user 对象并提取 id
                        api_user = None
                        try:
                            try:
                                await page.wait_for_function('localStorage.getItem("user") !== null', timeout=10000)
                            except Exception:
                                await page.wait_for_timeout(2000)

                            user_data = await page.evaluate("() => localStorage.getItem('user')")
                            if user_data:
                                user_obj = json.loads(user_data)
                                api_user = user_obj.get("id")
                                if api_user:
                                    print(f"✅ {self.account_name}: Got api user: {api_user}")
                                else:
                                    print(f"⚠️ {self.account_name}: User id not found in localStorage")
                            else:
                                print(f"⚠️ {self.account_name}: User data not found in localStorage")
                        except Exception as e:
                            print(f"⚠️ {self.account_name}: Error reading user from localStorage: {e}")

                        if api_user:
                            print(f"✅ {self.account_name}: OAuth authorization successful")

                            # 提取 session cookie，只保留与 provider domain 匹配的
                            restore_cookies = await page.context.cookies()
                            user_cookies = filter_cookies(restore_cookies, self.provider_config.origin)

                            return True, {"cookies": user_cookies, "api_user": api_user}
                        else:
                            print(f"⚠️ {self.account_name}: OAuth callback received but no user ID found")
                            await take_screenshot(page, "oauth_failed_no_user_id_bypass", self.account_name)
                            parsed_url = urlparse(page.url)
                            query_params = parse_qs(parsed_url.query)

                            # 如果 query 中包含 code，说明 OAuth 回调成功
                        if "code" in query_params:
                            print(f"✅ {self.account_name}: OAuth code received: {query_params.get('code')}")
                            return True, query_params
                        else:
                            print(f"❌ {self.account_name}: OAuth failed, no code in callback")
                            return False, _build_linuxdo_error(
                                "linuxdo_oauth_no_code",
                                "Linux.do OAuth 回调缺少 code",
                                "Linux.do OAuth failed - no code in callback",
                            )
                    else:
                        print(f"❌ {self.account_name}: Approve button not found")
                        await take_screenshot(page, "approve_button_not_found_bypass", self.account_name)
                        diagnosed = await _diagnose_linuxdo_page_issue(page)
                        if diagnosed:
                            return False, diagnosed
                        return False, _build_linuxdo_error(
                            "linuxdo_allow_button_not_found",
                            "Linux.do 授权页未找到允许按钮",
                            "Linux.do allow button not found",
                        )

                except Exception as e:
                    print(
                        f"❌ {self.account_name}: Error occurred during authorization: {e}\n\n"
                        f"Current page is: {page.url}"
                    )
                    await take_screenshot(page, "authorization_failed_bypass", self.account_name)
                    diagnosed = await _diagnose_linuxdo_page_issue(page)
                    if diagnosed:
                        diagnosed["error_detail"] = f"{diagnosed['error_detail']}; authorization exception: {e}"
                        diagnosed["error"] = diagnosed["error_detail"]
                        return False, diagnosed
                    return False, _build_linuxdo_error(
                        "linuxdo_authorization_failed",
                        "Linux.do 授权流程异常",
                        f"Linux.do authorization failed: {e}",
                    )

            except Exception as e:
                print(f"❌ {self.account_name}: Error occurred while processing linux.do page: {e}")
                await take_screenshot(page, "page_navigation_error_bypass", self.account_name)
                diagnosed = await _diagnose_linuxdo_page_issue(page)
                if diagnosed:
                    diagnosed["error_detail"] = f"{diagnosed['error_detail']}; page processing exception: {e}"
                    diagnosed["error"] = diagnosed["error_detail"]
                    return False, diagnosed
                return False, _build_linuxdo_error(
                    "linuxdo_page_navigation_error",
                    "Linux.do 页面导航异常",
                    f"Linux.do page navigation error: {e}",
                )
            finally:
                await page.close()
                await context.close()
