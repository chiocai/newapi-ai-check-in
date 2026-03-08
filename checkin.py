#!/usr/bin/env python3
"""
CheckIn 类
"""

import asyncio
import hashlib
import json
import os
import tempfile
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx
from camoufox.async_api import AsyncCamoufox

from utils.browser_utils import (
    aliyun_captcha_check,
    filter_cookies,
    get_random_user_agent,
    parse_cookies,
    save_page_content_to_file,
    take_screenshot,
)
from utils.config import AccountConfig, ProviderConfig
from utils.http_utils import proxy_resolve, response_resolve
from utils.topup import topup

if TYPE_CHECKING:
    from utils.linuxdo_session import LinuxDoSession

# Provider session 缓存有效期（秒）- 默认 23 小时
PROVIDER_SESSION_CACHE_TTL = 23 * 60 * 60
TIMEOUT_PAGE_LOAD = 60000
TIMEOUT_NAVIGATION = 45000


def _get_provider_session_cache_path(storage_dir: str, provider_name: str, username_hash: str) -> str:
    """获取 provider session 缓存文件路径"""
    return f"{storage_dir}/provider_{provider_name}_{username_hash}_session.json"


def _load_provider_session_cache(cache_path: str) -> dict | None:
    """加载 provider session 缓存

    Returns:
        dict | None: 缓存数据 {"cookies": dict, "api_user": str, "timestamp": float}，如果无效则返回 None
    """
    import time
    if not os.path.exists(cache_path):
        return None

    try:
        with open(cache_path, "r") as f:
            cache_data = json.load(f)

        # 检查缓存是否过期
        timestamp = cache_data.get("timestamp", 0)
        cache_age = time.time() - timestamp
        is_stale = cache_age > PROVIDER_SESSION_CACHE_TTL

        # 验证必要字段
        if "cookies" in cache_data and "api_user" in cache_data:
            if is_stale:
                print("ℹ️ Provider session cache expired by TTL, will try stale cache once before re-auth")
                cache_data["_stale"] = True
            else:
                cache_data["_stale"] = False
            return cache_data

        return None
    except Exception as e:
        print(f"⚠️ Failed to load provider session cache: {e}")
        return None


def _save_provider_session_cache(cache_path: str, cookies: dict, api_user: str | int) -> bool:
    """保存 provider session 缓存"""
    import time
    try:
        cache_data = {
            "cookies": cookies,
            "api_user": str(api_user),
            "timestamp": time.time(),
        }
        with open(cache_path, "w") as f:
            json.dump(cache_data, f, indent=2)
        return True
    except Exception as e:
        print(f"⚠️ Failed to save provider session cache: {e}")
        return False


def should_rebuild_provider_cache(provider_name: str, error_msg: str) -> bool:
    """判断是否应丢弃 provider cache 并重建"""
    normalized = (error_msg or "").lower()
    common_keywords = [
        "unauthorized",
        "401",
        "session",
        "invalid response format",
        "invalid response type",
        "failed to get user info",
        "waf",
        "未登录",
        "无权",
        "access token",
    ]
    if any(keyword in normalized for keyword in common_keywords):
        return True

    if provider_name == "anyrouter":
        anyrouter_keywords = [
            "http 403",
            "403",
            "text/html",
            "html response",
        ]
        return any(keyword in normalized for keyword in anyrouter_keywords)

    return False


def summarize_linuxdo_auth_state_error(error_msg: str) -> str:
    """归纳 Linux.do auth state 失败原因，便于通知摘要展示"""
    normalized = (error_msg or "").lower()

    if "http 403" in normalized or normalized.strip() == "403":
        return "站点 auth state 403/疑似 WAF 拦截"
    if "invalid response type" in normalized or "text/html" in normalized or "html" in normalized:
        return "站点 auth state 返回 HTML"
    if "cloudflare" in normalized:
        return "站点 auth state 被 Cloudflare 拦截"
    if "timeout" in normalized:
        return "站点 auth state 请求超时"
    if "failed to get state" in normalized:
        return "站点 auth state 浏览器获取失败"
    if "failed to get auth state" in normalized:
        return "站点 auth state 获取失败"

    return f"站点 auth state 异常: {error_msg}"


class CheckIn:
    """newapi.ai 签到管理类"""

    def __init__(
        self,
        account_name: str,
        account_config: AccountConfig,
        provider_config: ProviderConfig,
        global_proxy: dict | None = None,
        storage_state_dir: str = "storage-states",
        linuxdo_session: "LinuxDoSession | None" = None,
    ):
        """初始化签到管理器

        Args:
                account_info: account 用户配置
                proxy_config: 全局代理配置(可选)
                linuxdo_session: 共享的 Linux.do 会话（可选）
        """
        self.account_name = account_name
        self.safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)
        self.account_config = account_config
        self.provider_config = provider_config
        self.linuxdo_session = linuxdo_session

        # 代理优先级: 账号配置 > 全局配置
        self.camoufox_proxy_config = account_config.proxy if account_config.proxy else global_proxy
        # httpx.Client proxy 转换
        self.http_proxy_config = proxy_resolve(self.camoufox_proxy_config)

        # storage-states 目录
        self.storage_state_dir = storage_state_dir

        os.makedirs(self.storage_state_dir, exist_ok=True)

    async def get_waf_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取 WAF cookies（隐私模式）"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get WAF cookies (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_waf_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=True,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access console/personal page to get initial cookies")
                    await page.goto(self.provider_config.get_console_personal_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    cookies = await browser.cookies()

                    waf_cookies = {}
                    print(f"ℹ️ {self.account_name}: WAF cookies")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value})")
                        if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2", "cf_clearance", "__cf_bm"] and cookie_value is not None:
                            waf_cookies[cookie_name] = cookie_value

                    print(f"ℹ️ {self.account_name}: Got {len(waf_cookies)} WAF cookies after step 1")

                    # 检查是否至少获取到一个 WAF cookie
                    if not waf_cookies:
                        print(f"❌ {self.account_name}: No WAF cookies obtained")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(waf_cookies.keys())
                    print(f"✅ {self.account_name}: Successfully got WAF cookies: {cookie_names}")

                    return waf_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting WAF cookies: {e}")
                    return None
                finally:
                    await page.close()

    async def get_aliyun_captcha_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取阿里云验证 cookies"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get Aliyun captcha cookies (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_aliyun_captcha_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=True,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access console/personal page to get initial cookies")
                    await page.goto(self.provider_config.get_console_personal_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                        # # 提取验证码相关数据
                        # captcha_data = await page.evaluate(
                        #     """() => {
                        #     const data = {};

                        #     // 获取 traceid
                        #     const traceElement = document.getElementById('traceid');
                        #     if (traceElement) {
                        #         const text = traceElement.innerText || traceElement.textContent;
                        #         const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                        #         data.traceid = match ? match[1] : null;
                        #     }

                        #     // 获取 window.aliyun_captcha 相关字段
                        #     for (const key in window) {
                        #         if (key.startsWith('aliyun_captcha')) {
                        #             data[key] = window[key];
                        #         }
                        #     }

                        #     // 获取 requestInfo
                        #     if (window.requestInfo) {
                        #         data.requestInfo = window.requestInfo;
                        #     }

                        #     // 获取当前 URL
                        #     data.currentUrl = window.location.href;

                        #     return data;
                        # }"""
                        # )

                        # print(
                        #     f"📋 {self.account_name}: Captcha data extracted: " f"\n{json.dumps(captcha_data, indent=2)}"
                        # )

                        # # 通过 WaitForSecrets 发送验证码数据并等待用户手动验证
                        # from utils.wait_for_secrets import WaitForSecrets

                        # wait_for_secrets = WaitForSecrets()
                        # secret_obj = {
                        #     "CAPTCHA_NEXT_URL": {
                        #         "name": f"{self.account_name} - Aliyun Captcha Verification",
                        #         "description": (
                        #             f"Aliyun captcha verification required.\n"
                        #             f"TraceID: {captcha_data.get('traceid', 'N/A')}\n"
                        #             f"Current URL: {captcha_data.get('currentUrl', 'N/A')}\n"
                        #             f"Please complete the captcha manually in the browser, "
                        #             f"then provide the next URL after verification."
                        #         ),
                        #     }
                        # }

                        # secrets = wait_for_secrets.get(
                        #     secret_obj,
                        #     timeout=300,
                        #     notification={
                        #         "title": "阿里云验证",
                        #         "content": "请在浏览器中完成验证，并提供下一步的 URL。\n"
                        #         f"{json.dumps(captcha_data, indent=2)}\n"
                        #         "📋 操作说明：https://github.com/aceHubert/newapi-ai-check-in/docs/aliyun_captcha/README.md",
                        #     },
                        # )
                        # if not secrets or "CAPTCHA_NEXT_URL" not in secrets:
                        #     print(f"❌ {self.account_name}: No next URL provided " f"for captcha verification")
                        #     return None

                        # next_url = secrets["CAPTCHA_NEXT_URL"]
                        # print(f"🔄 {self.account_name}: Navigating to next URL " f"after captcha: {next_url}")

                        # # 导航到新的 URL
                        # await page.goto(next_url, wait_until="networkidle")

                        try:
                            await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                        except Exception:
                            await page.wait_for_timeout(3000)

                        # 再次检查是否还有 traceid
                        traceid_after = None
                        try:
                            traceid_after = await page.evaluate(
                                """() => {
                                const traceElement = document.getElementById('traceid');
                                if (traceElement) {
                                    const text = traceElement.innerText || traceElement.textContent;
                                    const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                                    return match ? match[1] : null;
                                }
                                return null;
                            }"""
                            )
                        except Exception:
                            traceid_after = None

                        if traceid_after:
                            print(
                                f"❌ {self.account_name}: Captcha verification failed, "
                                f"traceid still present: {traceid_after}"
                            )
                            return None

                        print(f"✅ {self.account_name}: Captcha verification successful, " f"traceid cleared")

                    cookies = await browser.cookies()

                    aliyun_captcha_cookies = {}
                    print(f"ℹ️ {self.account_name}: Aliyun Captcha cookies")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value})")
                        # if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"]
                        # and cookie_value is not None:
                        aliyun_captcha_cookies[cookie_name] = cookie_value

                    print(
                        f"ℹ️ {self.account_name}: "
                        f"Got {len(aliyun_captcha_cookies)} "
                        f"Aliyun Captcha cookies after step 1"
                    )

                    # 检查是否至少获取到一个 Aliyun Captcha cookie
                    if not aliyun_captcha_cookies:
                        print(f"❌ {self.account_name}: " f"No Aliyun Captcha cookies obtained")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(aliyun_captcha_cookies.keys())
                    print(f"✅ {self.account_name}: " f"Successfully got Aliyun Captcha cookies: {cookie_names}")

                    return aliyun_captcha_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: " f"Error occurred while getting Aliyun Captcha cookies, {e}")
                    return None
                finally:
                    await page.close()

    async def get_status_with_browser(self) -> dict | None:
        """使用 Camoufox 获取状态信息并缓存
        Returns:
            状态数据字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get status (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_status_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=True,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access console/personal page to get status from localStorage")
                    await page.goto(self.provider_config.get_console_personal_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 从 localStorage 获取 status
                    status_data = None
                    try:
                        status_str = await page.evaluate("() => localStorage.getItem('status')")
                        if status_str:
                            status_data = json.loads(status_str)
                            print(f"✅ {self.account_name}: Got status from localStorage")
                        else:
                            print(f"⚠️ {self.account_name}: No status found in localStorage")
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Error reading status from localStorage: {e}")

                    return status_data

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting status: {e}")
                    return None
                finally:
                    await page.close()

    async def get_auth_client_id(self, client: httpx.Client, headers: dict, provider: str) -> dict:
        """获取状态信息

        Args:
            client: httpx 客户端
            headers: 请求头
            provider: 提供商类型 (github/linuxdo)

        Returns:
            包含 success 和 client_id 或 error 的字典
        """
        try:
            response = client.get(self.provider_config.get_status_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                data = response_resolve(response, f"get_auth_client_id_{provider}", self.account_name)
                if data is None:

                    # 尝试从浏览器 localStorage 获取状态
                    # print(f"ℹ️ {self.account_name}: Getting status from browser")
                    # try:
                    #     status_data = await self.get_status_with_browser()
                    #     if status_data:
                    #         oauth = status_data.get(f"{provider}_oauth", False)
                    #         if not oauth:
                    #             return {
                    #                 "success": False,
                    #                 "error": f"{provider} OAuth is not enabled.",
                    #             }

                    #         client_id = status_data.get(f"{provider}_client_id", "")
                    #         if client_id:
                    #             print(f"✅ {self.account_name}: Got client ID from localStorage: " f"{client_id}")
                    #             return {
                    #                 "success": True,
                    #                 "client_id": client_id,
                    #             }
                    # except Exception as browser_err:
                    #     print(f"⚠️ {self.account_name}: Failed to get status from browser: " f"{browser_err}")

                    return {
                        "success": False,
                        "error": "Failed to get client id: Invalid response type (saved to logs)",
                    }

                if data.get("success"):
                    status_data = data.get("data", {})
                    oauth = status_data.get(f"{provider}_oauth", False)
                    if not oauth:
                        return {
                            "success": False,
                            "error": f"{provider} OAuth is not enabled.",
                        }

                    client_id = status_data.get(f"{provider}_client_id", "")
                    return {
                        "success": True,
                        "client_id": client_id,
                    }
                else:
                    error_msg = data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get client id: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get client id: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get client id, {e}",
            }

    async def get_auth_state_with_browser(self) -> dict:
        """使用 Camoufox 获取认证 URL 和 cookies

        Args:
            status: 要存储到 localStorage 的状态数据
            wait_for_url: 要等待的 URL 模式

        Returns:
            包含 success、url、cookies 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get auth state (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_auth_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=True,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
            ) as browser:
                page = await browser.new_page()

                try:
                    # 1. Open console/personal first，部分站点需从这里跳转后才会出现 LinuxDo 登录按钮
                    print(f"ℹ️ {self.account_name}: Opening console/personal page")
                    await page.goto(self.provider_config.get_console_personal_url(), wait_until="domcontentloaded")

                    # 等待页面稳定，避免执行上下文被销毁
                    await page.wait_for_timeout(3000)

                    # Wait for page to be fully loaded
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=10000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    # 再次等待确保页面稳定（避免重定向导致上下文销毁）
                    await page.wait_for_timeout(2000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    response = await page.evaluate(
                        f"""async () => {{
                            try{{
                                const response = await fetch('{self.provider_config.get_auth_state_url()}');
                                const data = await response.json();
                                return data;
                            }}catch(e){{
                                return {{
                                    success: false,
                                    message: e.message
                                }};
                            }}
                        }}"""
                    )

                    if response and "data" in response:
                        cookies = await browser.cookies()
                        return {
                            "success": True,
                            "state": response.get("data"),
                            "cookies": cookies,
                        }

                    return {"success": False, "error": f"Failed to get state, \n{json.dumps(response, indent=2)}"}

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get state, {e}")
                    await take_screenshot(page, "auth_url_error", self.account_name)
                    return {"success": False, "error": "Failed to get state"}
                finally:
                    await page.close()

    async def get_auth_state(
        self,
        client: httpx.Client,
        headers: dict,
    ) -> dict:
        """获取认证状态"""
        async def fallback_to_browser(reason: str) -> dict:
            print(f"⚠️ {self.account_name}: HTTP auth state failed ({reason}), fallback to browser auth state")
            auth_result = await self.get_auth_state_with_browser()
            if auth_result.get("success"):
                return auth_result
            error_msg = auth_result.get("error", "Unknown error")
            return {
                "success": False,
                "error": f"Failed to get auth state: {error_msg}",
            }

        try:
            response = client.get(self.provider_config.get_auth_state_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                json_data = response_resolve(response, "get_auth_state", self.account_name)
                if json_data is None:
                    return await fallback_to_browser("invalid response type")

                # 检查响应是否成功
                if json_data.get("success"):
                    auth_data = json_data.get("data")

                    # 将 httpx Cookies 对象转换为 Camoufox 格式
                    cookies = []
                    if response.cookies:
                        parsed_domain = urlparse(self.provider_config.origin).netloc

                        print(f"ℹ️ {self.account_name}: Got {len(response.cookies)} cookies from auth state request")
                        for cookie in response.cookies.jar:
                            http_only = cookie.httponly if cookie.has_nonstandard_attr("httponly") else False
                            same_site = cookie.samesite if cookie.has_nonstandard_attr("samesite") else "Lax"
                            print(
                                f"  📚 Cookie: {cookie.name} (Domain: {cookie.domain}, "
                                f"Path: {cookie.path}, Expires: {cookie.expires}, "
                                f"HttpOnly: {http_only}, Secure: {cookie.secure}, "
                                f"SameSite: {same_site})"
                            )
                            cookies.append(
                                {
                                    "name": cookie.name,
                                    "domain": cookie.domain if cookie.domain else parsed_domain,
                                    "value": cookie.value,
                                    "path": cookie.path,
                                    "expires": cookie.expires,
                                    "secure": cookie.secure,
                                    "httpOnly": http_only,
                                    "sameSite": same_site,
                                }
                            )

                    return {
                        "success": True,
                        "state": auth_data,
                        "cookies": cookies,  # 直接返回 Camoufox 格式的 cookies
                    }
                else:
                    error_msg = json_data.get("message", "Unknown error")
                    return await fallback_to_browser(error_msg)
            return await fallback_to_browser(f"HTTP {response.status_code}")
        except Exception as e:
            return await fallback_to_browser(str(e))

    async def complete_linuxdo_callback_with_browser(
        self,
        callback_url: str,
        auth_cookies: list[dict] | None = None,
    ) -> dict:
        """使用浏览器完成 LinuxDo OAuth callback，兼容部分站点的 JS / 重定向逻辑"""
        print(f"ℹ️ {self.account_name}: Trying browser-based OAuth callback fallback")
        async with AsyncCamoufox(
            headless=True,
            humanize=True,
            locale="en-US",
            geoip=True if self.camoufox_proxy_config else False,
            proxy=self.camoufox_proxy_config,
        ) as browser:
            context = await browser.new_context()
            page = await context.new_page()
            try:
                if auth_cookies:
                    await context.add_cookies(auth_cookies)
                    print(f"ℹ️ {self.account_name}: Added {len(auth_cookies)} auth cookies for callback fallback")

                await page.goto(callback_url, wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                await page.wait_for_timeout(5000)

                parsed = urlparse(self.provider_config.origin)
                if parsed.netloc not in page.url:
                    try:
                        await page.wait_for_url(f"**{parsed.netloc}/**", timeout=TIMEOUT_NAVIGATION)
                    except Exception:
                        pass

                api_user = None
                try:
                    user_data = await page.evaluate("() => localStorage.getItem('user')")
                    if user_data:
                        user_obj = json.loads(user_data)
                        api_user = user_obj.get("id")
                except Exception as e:
                    print(f"⚠️ {self.account_name}: Browser callback fallback failed to read localStorage user: {e}")

                if api_user:
                    restore_cookies = await page.context.cookies()
                    user_cookies = filter_cookies(restore_cookies, self.provider_config.origin)
                    print(f"✅ {self.account_name}: Browser callback fallback got api_user: {api_user}")
                    return {
                        "success": True,
                        "api_user": api_user,
                        "cookies": user_cookies,
                    }

                await save_page_content_to_file(page, "linuxdo_callback_browser_fallback_failed", self.account_name, prefix="linuxdo")
                await take_screenshot(page, "linuxdo_callback_browser_fallback_failed", self.account_name)
                return {"success": False, "error": "Browser callback fallback could not extract api_user"}
            finally:
                await page.close()
                await context.close()

    async def get_user_info_with_browser(
        self, auth_cookies: list[dict], api_user: str | int, do_checkin: bool = False
    ) -> dict:
        """使用 Camoufox 获取用户信息（可选执行签到）

        Args:
            auth_cookies: 认证 cookies 列表
            api_user: API 用户 ID
            do_checkin: 是否在获取用户信息前执行签到

        Returns:
            包含 success、quota、used_quota 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get user info (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_user_info_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=True,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
            ) as browser:
                page = await browser.new_page()

                # 添加 cookies 到浏览器上下文
                if auth_cookies:
                    print(f"ℹ️ {self.account_name}: Adding {len(auth_cookies)} cookies to browser")
                    await browser.add_cookies(auth_cookies)

                try:
                    # 1. 打开主页（使用 networkidle 等待网络请求完成，包括重定向）
                    print(f"ℹ️ {self.account_name}: Opening main page")
                    await page.goto(self.provider_config.origin, wait_until="networkidle", timeout=60000)

                    # 等待页面稳定，避免执行上下文被销毁
                    await page.wait_for_timeout(3000)

                    # 等待 URL 稳定（检测重定向是否完成）
                    last_url = page.url
                    for _ in range(5):
                        await page.wait_for_timeout(1000)
                        current_url = page.url
                        if current_url == last_url:
                            break
                        last_url = current_url
                        print(f"ℹ️ {self.account_name}: URL changed to {current_url}, waiting...")

                    print(f"ℹ️ {self.account_name}: Page stabilized at {page.url}")

                    # 等待页面完全加载
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=10000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    # 再次等待确保页面稳定
                    await page.wait_for_timeout(2000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 如果需要执行签到
                    if do_checkin:
                        print(f"🌐 {self.account_name}: Executing checkin via browser")
                        checkin_response = await page.evaluate(
                            f"""async () => {{
                                try {{
                                    const response = await fetch(
                                        '{self.provider_config.origin}/api/user/checkin',
                                        {{
                                            method: 'POST',
                                            headers: {{
                                                'Content-Type': 'application/json',
                                                'X-Requested-With': 'XMLHttpRequest',
                                                '{self.provider_config.api_user_key}': '{api_user}'
                                            }}
                                        }}
                                    );
                                    const data = await response.json();
                                    return data;
                                }} catch(e) {{
                                    return {{ success: false, message: e.message }};
                                }}
                            }}"""
                        )
                        if checkin_response:
                            if checkin_response.get("success"):
                                print(f"✅ {self.account_name}: Checkin successful - {checkin_response.get('message', '')}")
                            elif "已签到" in checkin_response.get("message", ""):
                                print(f"ℹ️ {self.account_name}: Already checked in - {checkin_response.get('message', '')}")
                            else:
                                print(f"⚠️ {self.account_name}: Checkin response - {checkin_response.get('message', '')}")

                    # 获取用户信息
                    response = await page.evaluate(
                        f"""async () => {{
                           const response = await fetch(
                               '{self.provider_config.get_user_info_url()}',
                               {{
                                   headers: {{
                                       '{self.provider_config.api_user_key}': '{api_user}'
                                   }}
                               }}
                           );
                           const data = await response.json();
                           return data;
                        }}"""
                    )

                    if response and "data" in response:
                        user_data = response.get("data", {})
                        quota = round(user_data.get("quota", 0) / 500000, 2)
                        used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                        bonus_quota = round(user_data.get("bonus_quota", 0) / 500000, 2)
                        print(
                            f"✅ {self.account_name}: "
                            f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}"
                        )
                        return {
                            "success": True,
                            "quota": quota,
                            "used_quota": used_quota,
                            "bonus_quota": bonus_quota,
                            "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                        }

                    return {
                        "success": False,
                        "error": f"Failed to get user info, \n{json.dumps(response, indent=2)}",
                    }

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get user info, {e}")
                    await take_screenshot(page, "user_info_error", self.account_name)
                    return {"success": False, "error": "Failed to get user info"}
                finally:
                    await page.close()

    async def get_user_info(self, client: httpx.Client, headers: dict) -> dict:
        """获取用户信息"""
        try:
            response = client.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                json_data = response_resolve(response, "get_user_info", self.account_name)
                if json_data is None:
                    # 尝试从浏览器获取用户信息
                    # print(f"ℹ️ {self.account_name}: Getting user info from browser")
                    # try:
                    #     user_info_result = await self.get_user_info_with_browser()
                    #     if user_info_result.get("success"):
                    #         return user_info_result
                    #     else:
                    #         error_msg = user_info_result.get("error", "Unknown error")
                    #         print(f"⚠️ {self.account_name}: {error_msg}")
                    # except Exception as browser_err:
                    #     print(
                    #         f"⚠️ {self.account_name}: "
                    #         f"Failed to get user info from browser: {browser_err}"
                    #     )

                    return {
                        "success": False,
                        "error": "Failed to get user info: Invalid response type (saved to logs)",
                    }

                if json_data.get("success"):
                    user_data = json_data.get("data", {})
                    quota = round(user_data.get("quota", 0) / 500000, 2)
                    used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                    bonus_quota = round(user_data.get("bonus_quota", 0) / 500000, 2)
                    return {
                        "success": True,
                        "quota": quota,
                        "used_quota": used_quota,
                        "bonus_quota": bonus_quota,
                        "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                    }
                else:
                    error_msg = json_data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get user info: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get user info: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get user info, {e}",
            }

    def execute_check_in(
        self,
        client: httpx.Client,
        headers: dict,
        api_user: str | int,
    ) -> tuple[bool, str]:
        """执行签到请求

        Returns:
            tuple[bool, str]: (成功标志, 错误消息或空字符串)
        """
        print(f"🌐 {self.account_name}: Executing check-in")

        checkin_headers = headers.copy()
        checkin_headers.update({"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"})

        response = client.post(self.provider_config.get_sign_in_url(api_user), headers=checkin_headers, timeout=30)

        print(f"📨 {self.account_name}: Response status code {response.status_code}")

        # 尝试解析响应（200 或 400 都可能包含有效的 JSON）
        if response.status_code in [200, 400]:
            json_data = response_resolve(response, "execute_check_in", self.account_name)
            if json_data is None:
                # 如果不是 JSON 响应（可能是 HTML），检查是否包含成功标识
                if "success" in response.text.lower():
                    print(f"✅ {self.account_name}: Check-in successful!")
                    return True, ""
                else:
                    print(f"❌ {self.account_name}: Check-in failed - Invalid response format")
                    return False, "Invalid response format"

            # 检查签到结果
            message = json_data.get("message", json_data.get("msg", ""))

            if (
                json_data.get("ret") == 1
                or json_data.get("code") == 0
                or json_data.get("success")
                or "已经签到" in message
            ):
                print(f"✅ {self.account_name}: Check-in successful!")
                return True, ""
            else:
                error_msg = json_data.get("msg", json_data.get("message", "Unknown error"))
                print(f"❌ {self.account_name}: Check-in failed - {error_msg}")
                return False, error_msg
        else:
            print(f"❌ {self.account_name}: Check-in failed - HTTP {response.status_code}")
            return False, f"HTTP {response.status_code}"

    async def execute_topup(
        self,
        headers: dict,
        cookies: dict,
        api_user: str | int,
        topup_interval: int = 60,
    ) -> dict:
        """执行完整的 CDK 获取和充值流程

        使用迭代器方式分步获取 CDK，每个 get_cdk 函数返回的 CDK 列表逐个执行 topup
        每次 topup 之间保持间隔时间，如果 topup 失败则停止

        Args:
            headers: 请求头
            cookies: cookies 字典
            api_user: API 用户 ID（通过参数传递，因为登录方式可能不同）
            topup_interval: 多次 topup 之间的间隔时间（秒），默认 60 秒

        Returns:
            包含 success, topup_count, errors 等信息的字典
        """
        http_proxy = proxy_resolve(self.camoufox_proxy_config)

        # 获取 topup URL
        topup_url = self.provider_config.get_topup_url()
        if not topup_url:
            print(f"❌ {self.account_name}: No topup URL configured for provider {self.provider_config.name}")
            return {
                "success": False,
                "topup_count": 0,
                "errors": ["No topup URL configured"],
            }

        # 构建 topup 请求头
        topup_headers = headers.copy()
        topup_headers.update({
            "Referer": f"{self.provider_config.origin}/console/topup",
            "Origin": self.provider_config.origin,
            self.provider_config.api_user_key: f"{api_user}",
        })

        results = {
            "success": True,
            "topup_count": 0,
            "topup_success_count": 0,
            "error": "",
        }

        # 使用迭代器方式分步获取 CDK
        # 每次迭代调用一个 get_cdk 函数，返回该函数的 CDK 列表
        topup_count = 0
        should_stop = False
        remaining_cdks: list[str] = []  # 收集剩余的 CDK

        async for cdk_list, _ in self.provider_config.iter_get_cdk(self.account_config):
            print(f"ℹ️ {self.account_name}: Got {len(cdk_list)} CDK(s) from current getter")
            
            # 遍历当前 get_cdk 函数返回的 CDK 列表
            for i, cdk in enumerate(cdk_list):
                # 如果不是第一个 CDK，等待间隔时间
                if topup_count > 0 and topup_interval > 0:
                    print(f"⏳ {self.account_name}: Waiting {topup_interval} seconds before next topup...")
                    await asyncio.sleep(topup_interval)

                topup_count += 1
                print(f"💰 {self.account_name}: Executing topup #{topup_count} with CDK: {cdk}")

                topup_result = topup(
                    account_name=self.account_name,
                    topup_url=topup_url,
                    headers=topup_headers,
                    cookies=cookies,
                    key=cdk,
                    proxy=http_proxy,
                )

                results["topup_count"] += 1

                if topup_result.get("success"):
                    results["topup_success_count"] += 1
                    if not topup_result.get("already_used"):
                        print(f"✅ {self.account_name}: Topup #{topup_count} successful")
                else:
                    # topup 失败，记录错误并停止
                    error_msg = topup_result.get("error", "Topup failed")
                    results["success"] = False
                    # 收集当前列表中剩余的 CDK（已获取但未执行 topup 的）
                    remaining_cdks = cdk_list[i + 1:]
                    print(f"❌ {self.account_name}: Topup #{topup_count} failed, stopping topup process")
                    should_stop = True
                    break
            
            # 如果需要停止，不再调用后续的 get_cdk 函数
            if should_stop:
                break

        # 将剩余 CDK 拼接到 error 中
        if remaining_cdks:
            remaining_cdks_str = ", ".join(remaining_cdks)
            results["error"] = f"{error_msg} | Remaining topup CDKs: {remaining_cdks_str}"
            print(f"⚠️ {self.account_name}: {len(remaining_cdks)} remaining CDK(s) not topuped: {remaining_cdks_str}")
        elif not results["success"]:
            # 没有剩余 CDK，但 topup 失败了
            results["error"] = error_msg

        if topup_count == 0:
            print(f"ℹ️ {self.account_name}: No CDK available for topup")
        elif results["topup_success_count"] > 0:
            print(f"✅ {self.account_name}: Total {results['topup_success_count']}/{results['topup_count']} topup(s) successful")

        return results

    async def check_in_with_cookies(self, cookies: dict, api_user: str | int) -> tuple[bool, dict]:
        """使用已有 cookies 执行签到操作"""
        print(
            f"ℹ️ {self.account_name}: Executing check-in with existing cookies (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(cookies)

            headers = {
                "User-Agent": get_random_user_agent(),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.get_login_url(),
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                self.provider_config.api_user_key: f"{api_user}",
            }

            if self.provider_config.needs_manual_check_in():
                success, error_msg = self.execute_check_in(client, headers, api_user)
                if not success:
                    return False, {"error": error_msg or "Check-in failed"}
            else:
                print(f"ℹ️ {self.account_name}: Check-in completed automatically (triggered by user info request)")

            # 如果账号配置启用了 New-API 通用签到功能
            # 对于 WAF 模式或 Turnstile 模式，签到将在浏览器中执行，这里跳过
            do_browser_checkin = False
            checkin_reward = None  # 保存签到奖励信息
            if self.account_config.checkin:
                if self.provider_config.needs_waf_cookies():
                    print(f"ℹ️ {self.account_name}: New-API checkin will be executed via browser (WAF bypass)")
                    do_browser_checkin = True
                elif self.provider_config.turnstile_site_key:
                    print(f"ℹ️ {self.account_name}: New-API checkin requires Turnstile, using browser...")
                    from utils.new_api_checkin import new_api_checkin_with_turnstile

                    checkin_result = await new_api_checkin_with_turnstile(
                        account_name=self.account_name,
                        origin=self.provider_config.origin,
                        api_user=api_user,
                        cookies=cookies,
                        turnstile_site_key=self.provider_config.turnstile_site_key,
                        proxy=self.camoufox_proxy_config,
                        api_user_key=self.provider_config.api_user_key,
                    )
                    if checkin_result.get("success"):
                        checkin_reward = checkin_result.get("reward")
                        if checkin_result.get("already_checked"):
                            checkin_reward = None
                    else:
                        error_msg = checkin_result.get("error", "New-API checkin failed")
                        print(f"❌ {self.account_name}: New-API checkin failed - {error_msg}")
                else:
                    print(f"ℹ️ {self.account_name}: New-API checkin enabled, executing...")
                    from utils.new_api_checkin import new_api_checkin

                    checkin_result = new_api_checkin(
                        account_name=self.account_name,
                        origin=self.provider_config.origin,
                        api_user=api_user,
                        headers=headers,
                        cookies=cookies,
                        proxy=self.http_proxy_config,
                        api_user_key=self.provider_config.api_user_key,
                    )
                    if checkin_result.get("success"):
                        # 保存签到奖励信息
                        checkin_reward = checkin_result.get("reward")
                        if checkin_result.get("already_checked"):
                            checkin_reward = None  # 已签到不显示奖励
                    else:
                        error_msg = checkin_result.get("error", "New-API checkin failed")
                        print(f"❌ {self.account_name}: New-API checkin failed - {error_msg}")
                        # 签到失败不阻止后续流程，只记录错误

            # 如果需要手动 topup（配置了 topup_path 和 get_cdk），执行 topup
            if self.provider_config.needs_manual_topup():
                print(f"ℹ️ {self.account_name}: Provider requires manual topup, executing...")
                topup_result = await self.execute_topup(headers, cookies, api_user)
                if topup_result.get("topup_count", 0) > 0:
                    print(
                        f"ℹ️ {self.account_name}: Topup completed - "
                        f"{topup_result.get('topup_success_count', 0)}/{topup_result.get('topup_count', 0)} successful"
                    )
                if not topup_result.get("success"):
                    error_msg = topup_result.get("error") or "Topup failed"
                    print(f"❌ {self.account_name}: Topup failed, stopping check-in process")
                    return False, {"error": error_msg}

            # 获取用户信息
            # anyrouter 特殊处理：虽然需要 WAF cookies，但直接使用 HTTP 请求获取用户信息
            # 其他需要绕过 WAF 的站点使用浏览器获取 user info（同时执行签到）
            if self.provider_config.name == "anyrouter":
                # anyrouter 优先使用 HTTP，请求失败时再回退浏览器
                print(f"ℹ️ {self.account_name}: Using HTTP request to get user info (anyrouter)")
                user_info = await self.get_user_info(client, headers)
                if not (user_info and user_info.get("success")):
                    print(f"⚠️ {self.account_name}: HTTP user info failed for anyrouter, fallback to browser")
                    auth_cookies_list = []
                    parsed_domain = urlparse(self.provider_config.origin).netloc
                    for name, value in cookies.items():
                        auth_cookies_list.append({
                            "name": name,
                            "value": value,
                            "domain": parsed_domain,
                            "path": "/",
                        })
                    browser_user_info = await self.get_user_info_with_browser(
                        auth_cookies_list,
                        api_user,
                        do_checkin=do_browser_checkin,
                    )
                    if browser_user_info and browser_user_info.get("success"):
                        user_info = browser_user_info
            elif self.provider_config.needs_waf_cookies():
                print(f"ℹ️ {self.account_name}: Using browser to get user info (WAF bypass)")
                # 将 cookies dict 转换为 Camoufox 格式的 list
                auth_cookies_list = []
                parsed_domain = urlparse(self.provider_config.origin).netloc
                for name, value in cookies.items():
                    auth_cookies_list.append({
                        "name": name,
                        "value": value,
                        "domain": parsed_domain,
                        "path": "/",
                    })
                user_info = await self.get_user_info_with_browser(auth_cookies_list, api_user, do_checkin=do_browser_checkin)
            else:
                user_info = await self.get_user_info(client, headers)
            if user_info and user_info.get("success"):
                # 将签到奖励信息添加到 user_info 中
                if checkin_reward is not None:
                    user_info["checkin_reward"] = checkin_reward
                success_msg = user_info.get("display", "User info retrieved successfully")
                print(f"✅ {self.account_name}: {success_msg}")
                return True, user_info
            elif user_info:
                error_msg = user_info.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": error_msg}
            else:
                return False, {"error": "No user info available"}

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Error occurred during check-in process"}
        finally:
            client.close()

    async def check_in_with_github(self, username: str, password: str, waf_cookies: dict) -> tuple[bool, dict]:
        """使用 GitHub 账号执行签到操作"""
        print(
            f"ℹ️ {self.account_name}: Executing check-in with GitHub account (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(waf_cookies)

            headers = {
                "User-Agent": get_random_user_agent(),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.get_login_url(),
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                self.provider_config.api_user_key: "-1",
            }

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.github_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.github_client_id,
                }
                print(f"ℹ️ {self.account_name}: Using GitHub client ID from config")
            else:
                client_id_result = await self.get_auth_client_id(client, headers, "github")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for GitHub: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get GitHub client ID"}

            # # 获取 OAuth 认证状态
            auth_state_result = await self.get_auth_state(
                client=client,
                headers=headers,
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for GitHub: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get GitHub auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/github_{username_hash}_storage_state.json"

            from sign_in_with_github import GitHubSignIn

            github = GitHubSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            success, result_data = await github.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result.get("state"),
                auth_cookies=auth_state_result.get("cookies", []),
                cache_file_path=cache_file_path,
            )

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                merged_cookies = {**waf_cookies, **user_cookies}
                return await self.check_in_with_cookies(merged_cookies, api_user)
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: Received OAuth code, calling callback API")

                callback_url = httpx.URL(self.provider_config.get_github_auth_url()).copy_with(params=result_data)
                print(f"ℹ️ {self.account_name}: Callback URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 httpx 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        client.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    response = client.get(callback_url, headers=headers, timeout=30)

                    if response.status_code == 200:
                        json_data = response_resolve(response, "github_oauth_callback", self.account_name)
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: Got api_user from callback: {api_user}")

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

                                print(
                                    f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} user cookies: {list(user_cookies.keys())}"
                                )
                                merged_cookies = {**waf_cookies, **user_cookies}
                                return await self.check_in_with_cookies(merged_cookies, api_user)
                            else:
                                print(f"❌ {self.account_name}: No user ID in callback response")
                                return False, {"error": "No user ID in OAuth callback response"}
                        else:
                            error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                            print(f"❌ {self.account_name}: OAuth callback failed: {error_msg}")
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    return False, {"error": f"OAuth callback error: {callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "GitHub check-in process error"}
        finally:
            client.close()

    async def check_in_with_linuxdo(
        self,
        username: str,
        password: str,
        waf_cookies: dict,
        login_only: bool = False,
    ) -> tuple[bool, dict]:
        """使用 Linux.do 账号执行签到操作

        Args:
            username: Linux.do 用户名
            password: Linux.do 密码
            waf_cookies: WAF cookies
            login_only: 如果为 True，只返回登录信息（cookies 和 api_user），不执行签到
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with Linux.do account (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        # 生成缓存文件路径
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        provider_cache_path = _get_provider_session_cache_path(
            self.storage_state_dir, self.provider_config.name, username_hash
        )

        # 尝试使用缓存的 provider session
        cached_session = _load_provider_session_cache(provider_cache_path)
        if cached_session:
            cached_cookies = cached_session["cookies"]
            cached_api_user = cached_session["api_user"]
            is_stale_cache = bool(cached_session.get("_stale"))
            if is_stale_cache:
                print(f"ℹ️ {self.account_name}: Found stale provider session cache, trying it before OAuth flow")
            else:
                print(f"✅ {self.account_name}: Found valid provider session cache, skipping OAuth flow")

            # 合并 WAF cookies 和缓存的 cookies
            merged_cookies = {**waf_cookies, **cached_cookies}

            # 如果只需要登录信息，直接返回
            if login_only:
                return True, {"cookies": merged_cookies, "api_user": cached_api_user}

            # 使用缓存的 cookies 执行签到
            success, result = await self.check_in_with_cookies(merged_cookies, cached_api_user)

            # 如果签到失败（可能是 session 过期或 WAF 挑战），清除缓存并重新登录
            if not success and "error" in result:
                error_msg = result.get("error", "").lower()
                if should_rebuild_provider_cache(self.provider_config.name, error_msg):
                    print(f"⚠️ {self.account_name}: Cached session may be expired or WAF challenge, clearing cache and re-authenticating")
                    try:
                        os.remove(provider_cache_path)
                    except Exception:
                        pass
                    if self.provider_config.name == "anyrouter":
                        from utils.linuxdo_session import LinuxDoSessionManager

                        print(f"ℹ️ {self.account_name}: anyrouter cache invalid, forcing LinuxDo shared session rebuild")
                        refreshed_session = await LinuxDoSessionManager.get_session(
                            username,
                            password,
                            proxy=self.camoufox_proxy_config,
                            auto_login=True,
                        )
                        if not getattr(refreshed_session, "is_logged_in", False):
                            return False, {
                                "error": (
                                    "anyrouter provider cache invalid and LinuxDo shared session is not warmed. "
                                    "Please run `uv run python prepare_linuxdo_session.py` first"
                                )
                            }
                        self.linuxdo_session = refreshed_session
                    # 继续执行下面的 OAuth 流程
                else:
                    return success, result
            else:
                if success and is_stale_cache:
                    _save_provider_session_cache(provider_cache_path, cached_cookies, cached_api_user)
                    print(f"✅ {self.account_name}: Stale provider session cache is still valid, timestamp refreshed")
                return success, result

        from utils.linuxdo_session import LinuxDoSessionManager

        circuit_reason = LinuxDoSessionManager.get_circuit_reason(username)
        if circuit_reason:
            return False, {
                "error_type": "linuxdo_circuit_open",
                "error_summary": "Linux.do OAuth 已熔断，本轮跳过",
                "error_detail": circuit_reason,
                "error": f"Linux.do circuit is open for this run: {circuit_reason}",
            }

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(waf_cookies)

            headers = {
                "User-Agent": get_random_user_agent(),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.get_login_url(),
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                self.provider_config.api_user_key: "-1",
            }

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.linuxdo_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.linuxdo_client_id,
                }
                print(f"ℹ️ {self.account_name}: Using Linux.do client ID from config")
            else:
                client_id_result = await self.get_auth_client_id(client, headers, "linuxdo")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for Linux.do: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {
                        "error_type": "linuxdo_client_id_failed",
                        "error_summary": "站点 Linux.do client_id 获取失败",
                        "error_detail": error_msg,
                        "error": f"Failed to get Linux.do client ID: {error_msg}",
                    }

            # 获取 OAuth 认证状态
            # 如果需要绕过 WAF，使用浏览器获取 auth state
            if self.provider_config.needs_waf_cookies():
                print(f"ℹ️ {self.account_name}: Using browser to get auth state (WAF bypass)")
                auth_state_result = await self.get_auth_state_with_browser()
            else:
                auth_state_result = await self.get_auth_state(
                    client=client,
                    headers=headers,
                )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for Linux.do: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {
                    "error_type": "linuxdo_auth_state_failed",
                    "error_summary": summarize_linuxdo_auth_state_error(error_msg),
                    "error_detail": error_msg,
                    "error": f"Failed to get Linux.do auth state: {error_msg}",
                }

            # 生成 Linux.do storage state 缓存文件路径
            cache_file_path = f"{self.storage_state_dir}/linuxdo_{username_hash}_storage_state.json"

            from sign_in_with_linuxdo import LinuxDoSignIn

            linuxdo = LinuxDoSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
                shared_session=self.linuxdo_session,
            )

            success, result_data = await linuxdo.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result["state"],
                auth_cookies=auth_state_result.get("cookies", []),
                cache_file_path=cache_file_path,
            )

            if not success and isinstance(result_data, dict):
                error_type = result_data.get("error_type", "")
                if error_type in {"linuxdo_high_load", "linuxdo_sso_provider_stuck", "linuxdo_redirect_login"}:
                    LinuxDoSessionManager.trip_circuit(
                        username,
                        result_data.get("error_detail") or result_data.get("error_summary") or error_type,
                    )

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]
                merged_cookies = {**waf_cookies, **user_cookies}

                # 保存 provider session 缓存
                _save_provider_session_cache(provider_cache_path, user_cookies, api_user)
                print(f"✅ {self.account_name}: Provider session cached for future use")

                # 如果只需要登录信息，直接返回
                if login_only:
                    return True, {"cookies": merged_cookies, "api_user": api_user}

                # 统一调用 check_in_with_cookies 执行签到
                return await self.check_in_with_cookies(merged_cookies, api_user)
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: Received OAuth code, calling callback API")

                callback_url = httpx.URL(self.provider_config.get_linuxdo_auth_url()).copy_with(params=result_data)
                print(f"ℹ️ {self.account_name}: Callback URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 httpx 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        client.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    response = client.get(callback_url, headers=headers, timeout=30)

                    if response.status_code == 200:
                        json_data = response_resolve(response, "linuxdo_oauth_callback", self.account_name)
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: Got api_user from callback: {api_user}")

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

                                print(
                                    f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} user cookies: {list(user_cookies.keys())}"
                                )
                                merged_cookies = {**waf_cookies, **user_cookies}

                                # 保存 provider session 缓存
                                _save_provider_session_cache(provider_cache_path, user_cookies, api_user)
                                print(f"✅ {self.account_name}: Provider session cached for future use")

                                # 如果只需要登录信息，直接返回
                                if login_only:
                                    return True, {"cookies": merged_cookies, "api_user": api_user}

                                return await self.check_in_with_cookies(merged_cookies, api_user)
                            else:
                                print(f"❌ {self.account_name}: No user ID in callback response")
                                return False, {"error": "No user ID in OAuth callback response"}
                        else:
                            error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                            print(f"❌ {self.account_name}: OAuth callback failed: {error_msg}")
                            fallback_result = await self.complete_linuxdo_callback_with_browser(
                                str(callback_url),
                                auth_state_result.get("cookies", []),
                            )
                            if fallback_result.get("success"):
                                merged_cookies = {**waf_cookies, **fallback_result["cookies"]}
                                api_user = fallback_result["api_user"]
                                _save_provider_session_cache(provider_cache_path, fallback_result["cookies"], api_user)
                                print(f"✅ {self.account_name}: Browser callback fallback succeeded")
                                if login_only:
                                    return True, {"cookies": merged_cookies, "api_user": api_user}
                                return await self.check_in_with_cookies(merged_cookies, api_user)
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        fallback_result = await self.complete_linuxdo_callback_with_browser(
                            str(callback_url),
                            auth_state_result.get("cookies", []),
                        )
                        if fallback_result.get("success"):
                            merged_cookies = {**waf_cookies, **fallback_result["cookies"]}
                            api_user = fallback_result["api_user"]
                            _save_provider_session_cache(provider_cache_path, fallback_result["cookies"], api_user)
                            print(f"✅ {self.account_name}: Browser callback fallback succeeded")
                            if login_only:
                                return True, {"cookies": merged_cookies, "api_user": api_user}
                            return await self.check_in_with_cookies(merged_cookies, api_user)
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    fallback_result = await self.complete_linuxdo_callback_with_browser(
                        str(callback_url),
                        auth_state_result.get("cookies", []),
                    )
                    if fallback_result.get("success"):
                        merged_cookies = {**waf_cookies, **fallback_result["cookies"]}
                        api_user = fallback_result["api_user"]
                        _save_provider_session_cache(provider_cache_path, fallback_result["cookies"], api_user)
                        print(f"✅ {self.account_name}: Browser callback fallback succeeded")
                        if login_only:
                            return True, {"cookies": merged_cookies, "api_user": api_user}
                        return await self.check_in_with_cookies(merged_cookies, api_user)
                    return False, {"error": f"OAuth callback error: {callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Linux.do check-in process error"}

    async def execute(self) -> list[tuple[str, bool, dict | None]]:
        """为单个账号执行签到操作，支持多种认证方式"""
        print(f"\n\n⏳ Starting to process {self.account_name}")

        waf_cookies = {}
        if self.provider_config.needs_waf_cookies():
            waf_cookies = await self.get_waf_cookies_with_browser()
            if not waf_cookies:
                print(f"⚠️ {self.account_name}: Unable to get WAF cookies, continuing with empty cookies")
                waf_cookies = {}  # 确保 waf_cookies 是空字典而不是 None
            else:
                print(f"✅ {self.account_name}: WAF cookies obtained")
        else:
            print(f"ℹ️ {self.account_name}: Bypass WAF not required, using user cookies directly")

        # 解析账号配置
        cookies_data = self.account_config.cookies
        github_info = self.account_config.github
        linuxdo_info = self.account_config.linux_do
        results = []

        # 尝试 cookies 认证
        if cookies_data:
            print(f"\nℹ️ {self.account_name}: Trying cookies authentication")
            try:
                user_cookies = parse_cookies(cookies_data)
                if not user_cookies:
                    print(f"❌ {self.account_name}: Invalid cookies format")
                    results.append(("cookies", False, {"error": "Invalid cookies format"}))
                else:
                    api_user = self.account_config.api_user
                    if not api_user:
                        print(f"❌ {self.account_name}: API user identifier not found for cookies")
                        results.append(("cookies", False, {"error": "API user identifier not found"}))
                    else:
                        # 使用已有 cookies 执行签到
                        all_cookies = {**waf_cookies, **user_cookies}
                        success, user_info = await self.check_in_with_cookies(all_cookies, api_user)
                        if success:
                            print(f"✅ {self.account_name}: Cookies authentication successful")
                            results.append(("cookies", True, user_info))
                        else:
                            print(f"❌ {self.account_name}: Cookies authentication failed")
                            results.append(("cookies", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: Cookies authentication error: {e}")
                results.append(("cookies", False, {"error": str(e)}))

        # 尝试 GitHub 认证
        if github_info:
            print(f"\nℹ️ {self.account_name}: Trying GitHub authentication")
            try:
                username = github_info.get("username")
                password = github_info.get("password")
                if not username or not password:
                    print(f"❌ {self.account_name}: Incomplete GitHub account information")
                    results.append(("github", False, {"error": "Incomplete GitHub account information"}))
                else:
                    # 使用 GitHub 账号执行签到
                    success, user_info = await self.check_in_with_github(username, password, waf_cookies)
                    if success:
                        print(f"✅ {self.account_name}: GitHub authentication successful")
                        results.append(("github", True, user_info))
                    else:
                        print(f"❌ {self.account_name}: GitHub authentication failed")
                        results.append(("github", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: GitHub authentication error: {e}")
                results.append(("github", False, {"error": str(e)}))

        # 尝试 Linux.do 认证
        if linuxdo_info:
            print(f"\nℹ️ {self.account_name}: Trying Linux.do authentication")
            try:
                username = linuxdo_info.get("username")
                password = linuxdo_info.get("password")
                if not username or not password:
                    print(f"❌ {self.account_name}: Incomplete Linux.do account information")
                    results.append(("linux.do", False, {"error": "Incomplete Linux.do account information"}))
                # 特殊处理：有 get_cdk 的 provider（如 b4u, fuli_wheel, x666）
                # 这类 provider 的签到通过 get_cdk 函数完成
                elif self.provider_config.get_cdk:
                    print(f"ℹ️ {self.account_name}: Provider uses get_cdk for check-in")
                    try:
                        # 直接调用 get_cdk 完成签到
                        cdk_results = []  # CDK 字符串列表，用于 topup
                        raw_results = []  # 原始返回值，用于通知展示
                        async for cdks, raw_result in self.provider_config.iter_get_cdk(self.account_config):
                            cdk_results.extend(cdks)
                            raw_results.append(raw_result)

                        if raw_results:
                            if cdk_results:
                                print(f"✅ {self.account_name}: get_cdk completed with {len(cdk_results)} result(s)")
                            else:
                                print(f"✅ {self.account_name}: get_cdk completed with {len(raw_results)} raw result(s)")

                            # 如果需要 topup（有 topup_path 和 linuxdo_client_id），执行 CDK 兑换
                            if self.provider_config.needs_manual_topup() and self.provider_config.linuxdo_client_id and cdk_results:
                                print(f"ℹ️ {self.account_name}: Provider requires CDK topup, logging in to main site...")

                                # 使用 LinuxDo 登录主站获取 session
                                main_site_cookies = None
                                main_site_api_user = None

                                # 优先使用已配置的 cookies
                                if cookies_data:
                                    user_cookies = parse_cookies(cookies_data)
                                    api_user = self.account_config.api_user
                                    if user_cookies and api_user:
                                        print(f"ℹ️ {self.account_name}: Using configured cookies for main site")
                                        main_site_cookies = {**waf_cookies, **user_cookies}
                                        main_site_api_user = api_user

                                # 如果没有配置 cookies，使用标准 LinuxDo OAuth 登录主站
                                if not main_site_cookies:
                                    print(f"ℹ️ {self.account_name}: Auto-login to main site using LinuxDo OAuth")
                                    try:
                                        # 复用标准的 LinuxDo OAuth 登录流程，只获取登录信息不执行签到
                                        success, login_result = await self.check_in_with_linuxdo(
                                            username,
                                            password,
                                            waf_cookies,
                                            login_only=True,
                                        )
                                        if success and isinstance(login_result, dict):
                                            if "cookies" in login_result and "api_user" in login_result:
                                                # 转换 cookies 格式：从 [{name, value, ...}, ...] 到 {name: value}
                                                raw_cookies = login_result.get("cookies")
                                                if isinstance(raw_cookies, list):
                                                    main_site_cookies = {c["name"]: c["value"] for c in raw_cookies if "name" in c and "value" in c}
                                                elif isinstance(raw_cookies, dict):
                                                    main_site_cookies = raw_cookies
                                                else:
                                                    main_site_cookies = {}
                                                main_site_api_user = login_result.get("api_user")
                                                print(f"✅ {self.account_name}: Main site login successful, api_user: {main_site_api_user}")
                                            else:
                                                print(f"❌ {self.account_name}: Login result missing cookies or api_user: {login_result}")
                                        else:
                                            print(f"❌ {self.account_name}: Failed to login to main site: {login_result}")
                                    except Exception as e:
                                        print(f"❌ {self.account_name}: Main site login error: {e}")

                                # 执行 topup
                                if main_site_cookies and main_site_api_user:
                                    headers = {
                                        "User-Agent": get_random_user_agent(),
                                        "Accept": "application/json, text/plain, */*",
                                        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                                        "Referer": f"{self.provider_config.origin}/console/topup",
                                        "Origin": self.provider_config.origin,
                                        self.provider_config.api_user_key: f"{main_site_api_user}",
                                    }

                                    topup_success_count = 0
                                    for i, cdk in enumerate(cdk_results):
                                        if i > 0:
                                            await asyncio.sleep(2)

                                        print(f"💰 {self.account_name}: Topup CDK #{i+1}/{len(cdk_results)}: {cdk}")
                                        topup_result = topup(
                                            account_name=self.account_name,
                                            topup_url=self.provider_config.get_topup_url(),
                                            headers=headers,
                                            cookies=main_site_cookies,
                                            key=cdk,
                                            proxy=None,  # 主站不使用代理
                                        )

                                        if topup_result.get("success"):
                                            topup_success_count += 1
                                            print(f"✅ {self.account_name}: CDK #{i+1} topup successful")
                                        else:
                                            error_msg = topup_result.get("error", "Unknown error")
                                            print(f"❌ {self.account_name}: CDK #{i+1} topup failed: {error_msg}")

                                    print(f"ℹ️ {self.account_name}: Topup completed - {topup_success_count}/{len(cdk_results)} successful")
                                else:
                                    print(f"⚠️ {self.account_name}: Failed to get main site credentials, CDKs not redeemed")

                            results.append(("linux.do", True, {"success": True, "cdk_results": raw_results}))
                        else:
                            print(f"❌ {self.account_name}: get_cdk returned no result")
                            results.append(("linux.do", False, {"error": "get_cdk returned no result"}))
                    except Exception as cdk_err:
                        print(f"❌ {self.account_name}: get_cdk failed: {cdk_err}")
                        results.append(("linux.do", False, {"error": f"get_cdk failed: {cdk_err}"}))
                else:
                    # 使用 Linux.do 账号执行签到（标准 OAuth 流程）
                    success, user_info = await self.check_in_with_linuxdo(
                        username,
                        password,
                        waf_cookies,
                    )
                    if success:
                        print(f"✅ {self.account_name}: Linux.do authentication successful")
                        results.append(("linux.do", True, user_info))
                    else:
                        print(f"❌ {self.account_name}: Linux.do authentication failed")
                        results.append(("linux.do", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: Linux.do authentication error: {e}")
                results.append(("linux.do", False, {"error": str(e)}))

        if not results:
            print(f"❌ {self.account_name}: No valid authentication method found in configuration")
            return []

        # 输出最终结果
        print(f"\n📋 {self.account_name} authentication results:")
        successful_count = 0
        for auth_method, success, user_info in results:
            status = "✅" if success else "❌"
            print(f"  {status} {auth_method} authentication")
            if success:
                successful_count += 1

        print(f"\n🎯 {self.account_name}: {successful_count}/{len(results)} authentication methods successful")

        return results

   
