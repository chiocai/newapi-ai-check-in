#!/usr/bin/env python3
"""
使用 Camoufox 绕过 Cloudflare 验证执行 Linux.do 签到
"""

import json
import os
import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urlparse, parse_qs
from camoufox.async_api import AsyncCamoufox
from utils.browser_utils import filter_cookies, take_screenshot, save_page_content_to_file
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
        cache_file_path: str = "",
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
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                if attempt > 1:
                    print(f"ℹ️ {self.account_name}: Retry attempt {attempt}/{MAX_RETRIES}")
                    await asyncio.sleep(RETRY_DELAY)

                result = await self._signin_impl(client_id, auth_state, auth_cookies, cache_file_path)
                if result[0]:  # 成功
                    return result
                else:
                    last_error = result[1].get("error", "Unknown error")
                    # 某些错误不需要重试
                    if "not found" in str(last_error).lower():
                        print(f"❌ {self.account_name}: Non-retryable error: {last_error}")
                        return result
                    print(f"⚠️ {self.account_name}: Attempt {attempt} failed: {last_error}")

            except Exception as e:
                last_error = str(e)
                print(f"⚠️ {self.account_name}: Attempt {attempt} exception: {e}")

        print(f"❌ {self.account_name}: All {MAX_RETRIES} attempts failed. Last error: {last_error}")
        return False, {"error": f"All {MAX_RETRIES} attempts failed: {last_error}"}

    async def _signin_impl(
        self,
        client_id: str,
        auth_state: str,
        auth_cookies: list,
        cache_file_path: str = "",
    ) -> tuple[bool, dict]:
        """实际的登录实现"""
        print(f"ℹ️ {self.account_name}: Executing sign-in with Linux.do")
        print(
            f"ℹ️ {self.account_name}: Using client_id: {client_id}, auth_state: {auth_state}, cache_file: {cache_file_path}"
        )

        # 确定 storage_state 来源：优先使用共享会话
        storage_state = None
        if self.shared_session:
            shared_state_path = self.shared_session.get_storage_state_path()
            if os.path.exists(shared_state_path):
                storage_state = shared_state_path
                print(f"ℹ️ {self.account_name}: Using shared session storage state")

        if not storage_state and cache_file_path and os.path.exists(cache_file_path):
            storage_state = cache_file_path
            print(f"ℹ️ {self.account_name}: Found cache file, restore storage state")

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

                if os.path.exists(cache_file_path):
                    try:
                        print(f"ℹ️ {self.account_name}: Checking login status at {oauth_url}")
                        # 直接访问授权页面检查是否已登录
                        response = await page.goto(oauth_url, wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
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

                        # 登录后可能直接跳转回应用页面
                        if response and response.url.startswith(self.provider_config.origin):
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
                                print(f"ℹ️ {self.account_name}: Cache session expired, need to login again")
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Failed to check login status: {e}")

                # 如果未登录，则执行登录流程
                if not is_logged_in:
                    try:
                        print(f"ℹ️ {self.account_name}: Starting to sign in linux.do")

                        await page.goto("https://linux.do/login", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)

                        # 等待登录表单加载
                        try:
                            await page.wait_for_selector("#login-account-name", timeout=TIMEOUT_ELEMENT_WAIT)
                        except Exception:
                            print(f"⚠️ {self.account_name}: Login form not found, page may be loading slowly")
                            await page.wait_for_timeout(2000)

                        await page.fill("#login-account-name", self.username, timeout=TIMEOUT_FILL)
                        await page.wait_for_timeout(500)
                        await page.fill("#login-account-password", self.password, timeout=TIMEOUT_FILL)
                        await page.wait_for_timeout(500)
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

                        # 保存新的会话状态
                        await context.storage_state(path=cache_file_path)
                        print(f"✅ {self.account_name}: Storage state saved to cache file")

                    except Exception as e:
                        print(f"❌ {self.account_name}: Error occurred while signing in linux.do: {e}")
                        await take_screenshot(page, "signin_bypass_error", self.account_name)
                        return False, {"error": "Linux.do sign-in error"}

                    # 登录后访问授权页面
                    try:
                        print(f"ℹ️ {self.account_name}: Navigating to authorization page: {oauth_url}")
                        await page.goto(oauth_url, wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                    except Exception as e:
                        print(f"❌ {self.account_name}: Failed to navigate to authorization page: {e}")
                        await take_screenshot(page, "auth_page_navigation_failed_bypass", self.account_name)
                        return False, {"error": "Linux.do authorization page navigation failed"}

                # 统一处理授权逻辑（无论是否通过缓存登录）
                try:
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
                                return False, {
                                    "error": "Linux.do OAuth failed - no code in callback",
                                }
                    else:
                        print(f"❌ {self.account_name}: Approve button not found")
                        await take_screenshot(page, "approve_button_not_found_bypass", self.account_name)
                        return False, {"error": "Linux.do allow button not found"}

                except Exception as e:
                    print(
                        f"❌ {self.account_name}: Error occurred during authorization: {e}\n\n"
                        f"Current page is: {page.url}"
                    )
                    await take_screenshot(page, "authorization_failed_bypass", self.account_name)
                    return False, {"error": "Linux.do authorization failed"}

            except Exception as e:
                print(f"❌ {self.account_name}: Error occurred while processing linux.do page: {e}")
                await take_screenshot(page, "page_navigation_error_bypass", self.account_name)
                return False, {"error": "Linux.do page navigation error"}
            finally:
                await page.close()
                await context.close()
