#!/usr/bin/env python3
"""
CheckIn 类
"""

import asyncio
import copy
import hashlib
import json
import os
import tempfile
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

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
from utils.debug_flags import linuxdo_auth_debug_enabled
from utils.http_utils import proxy_resolve, response_resolve
from utils.linuxdo_runtime_modes import (
    CHECKIN_MODE_BROWSER_FIRST,
    clear_checkin_browser_first,
    get_linuxdo_runtime_modes,
    mark_callback_browser_complete,
    mark_checkin_browser_first,
)
from utils.topup import topup

if TYPE_CHECKING:
    from utils.linuxdo_session import LinuxDoSession

# Provider session 缓存有效期（秒）- 默认 23 小时
PROVIDER_SESSION_CACHE_TTL = 23 * 60 * 60
TIMEOUT_PAGE_LOAD = 60000
TIMEOUT_NAVIGATION = 45000
SAFE_HTTP_ACCEPT_ENCODING = "gzip, deflate"


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


def has_provider_bypass_cookies(cookies: dict | None) -> bool:
    """判断当前 cookies 是否已携带可复用的 WAF/CF 绕过态"""
    if not isinstance(cookies, dict):
        return False

    bypass_cookie_names = {
        "cf_clearance",
        "__cf_bm",
        "acw_tc",
        "cdn_sec_tc",
        "acw_sc__v2",
    }
    return any(name in cookies and cookies.get(name) for name in bypass_cookie_names)


def should_retry_newapi_checkin_in_browser(error_msg: str) -> bool:
    """判断 New-API 签到失败后是否值得再起浏览器补救"""
    normalized = (error_msg or "").strip().lower()
    if not normalized:
        return False

    no_retry_indicators = [
        "当前余额高于签到阈值",
        "余额高于签到阈值",
        "签到功能未启用",
        "今日已签到",
        "已经签到",
        "already checked",
        "already signed",
        "not enabled",
        "threshold",
    ]
    if any(indicator.lower() in normalized for indicator in no_retry_indicators):
        return False

    retry_indicators = [
        "http 401",
        "http 403",
        "http 429",
        "http 500",
        "http 502",
        "http 503",
        "invalid response",
        "text/html",
        "html",
        "unauthorized",
        "cloudflare",
        "challenge",
        "waf",
        "forbidden",
        "timeout",
        "未登录",
        "无权",
        "会话",
    ]
    return any(indicator in normalized for indicator in retry_indicators)


def get_linuxdo_frontend_callback_url(provider_config: ProviderConfig, params: dict) -> str:
    """构造前端 LinuxDo OAuth 回调地址，优先使用 /oauth/linuxdo"""
    auth_path = provider_config.linuxdo_auth_path or "/api/oauth/linuxdo"
    if auth_path.startswith("/api/"):
        frontend_path = auth_path[4:]
    elif auth_path.startswith("/api"):
        frontend_path = auth_path[4:] or "/oauth/linuxdo"
    else:
        frontend_path = auth_path
    return str(httpx.URL(f"{provider_config.origin}{frontend_path}").copy_with(params=params))


def should_retry_linuxdo_auth_state_failure(error_msg: str) -> bool:
    """判断 auth state 失败后是否值得再重试一轮完整 OAuth"""
    normalized = (error_msg or "").lower()
    non_retry_indicators = [
        "ns_error_net_timeout",
        "ns_error_net_interrupt",
        "unexpected_eof_while_reading",
        "connection reset",
        "tlsv1 alert",
        "certificate verify failed",
        "name or service not known",
        "temporary failure in name resolution",
    ]
    return not any(indicator in normalized for indicator in non_retry_indicators)


def should_try_browser_callback_fallback(original_error_msg: str, frontend_http_error_msg: str | None = None) -> bool:
    """判断 HTTP callback 失败后是否值得再起浏览器前端 callback 兜底"""
    merged = " ".join(item for item in [original_error_msg, frontend_http_error_msg] if item).lower()
    non_retry_indicators = [
        "无法连接至 linux do 服务器",
        "state parameter is empty or mismatched",
        "frontend-first api callback returned no user id",
    ]
    return not any(indicator in merged for indicator in non_retry_indicators)


def should_force_browser_callback_fallback_for_provider(provider_origin: str) -> bool:
    """判断当前站点是否应在 callback 403 后保留浏览器前端回调兜底"""
    raw_hosts = os.getenv('LINUXDO_BROWSER_CALLBACK_FALLBACK_HOSTS', 'api.einzieg.site')
    allowed_hosts = {
        item.strip().lower()
        for item in raw_hosts.split(',')
        if item.strip()
    }
    return urlparse(provider_origin).netloc.lower() in allowed_hosts


def should_prefer_browser_first_newapi_checkin(provider_config: ProviderConfig, runtime_modes: dict | None = None) -> bool:
    """判断当前站点是否应默认浏览器优先执行 New-API 签到"""
    runtime_modes = runtime_modes or {}
    if runtime_modes.get('checkin_mode') == CHECKIN_MODE_BROWSER_FIRST:
        return True

    return (provider_config.checkin_mode or '').strip().lower() == 'browser-first'


def should_validate_provider_session_before_reuse(provider_config: ProviderConfig) -> bool:
    """判断当前站点是否应在复用 provider session cache 前先验证登录态"""
    return (provider_config.cache_reuse_mode or '').strip().lower() == 'validate-before-use'


def should_prefetch_waf_before_cached_session_use(provider_config: ProviderConfig) -> bool:
    """判断当前站点是否应在复用 cached session 前先补 WAF cookie"""
    return (provider_config.cache_waf_mode or '').strip().lower() == 'prefetch-before-reuse'


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
        self._active_linuxdo_username_hash: str | None = None
        self._site_mode_suggestions: dict[str, dict] = {}

        os.makedirs(self.storage_state_dir, exist_ok=True)

    def _get_linuxdo_runtime_modes_state_file(self) -> str:
        return os.path.join(self.storage_state_dir, 'linuxdo_runtime_modes.json')

    def _get_active_linuxdo_runtime_modes(self) -> dict:
        if not self._active_linuxdo_username_hash:
            return {}
        return get_linuxdo_runtime_modes(
            self.provider_config.origin,
            self._active_linuxdo_username_hash,
            self._get_linuxdo_runtime_modes_state_file(),
        )

    def _mark_active_callback_browser_complete(self, reason: str) -> None:
        if not self._active_linuxdo_username_hash:
            return
        mark_callback_browser_complete(
            self.provider_config.origin,
            self._active_linuxdo_username_hash,
            reason,
            self._get_linuxdo_runtime_modes_state_file(),
        )
        if (self.provider_config.callback_mode or '').strip().lower() != 'browser-complete':
            self._suggest_site_mode('callback_mode', 'browser-complete', reason)

    def _mark_active_browser_first_checkin(self, reason: str) -> None:
        if not self._active_linuxdo_username_hash:
            return
        mark_checkin_browser_first(
            self.provider_config.origin,
            self._active_linuxdo_username_hash,
            reason,
            self._get_linuxdo_runtime_modes_state_file(),
        )
        if (self.provider_config.checkin_mode or '').strip().lower() != 'browser-first':
            self._suggest_site_mode('checkin_mode', 'browser-first', reason)

    def _clear_active_browser_first_checkin(self) -> None:
        if not self._active_linuxdo_username_hash:
            return
        clear_checkin_browser_first(
            self.provider_config.origin,
            self._active_linuxdo_username_hash,
            self._get_linuxdo_runtime_modes_state_file(),
        )

    def _suggest_site_mode(self, option: str, value: str, reason: str) -> None:
        existing = self._site_mode_suggestions.get(option)
        if existing and existing.get('value') == value:
            return
        self._site_mode_suggestions[option] = {
            'option': option,
            'value': value,
            'reason': reason,
            'provider': self.provider_config.name,
            'site_origin': self.provider_config.origin,
        }
        print(
            f"💡 {self.account_name}: Site mode suggestion -> {option}={value} "
            f"({reason})"
        )

    def get_site_mode_suggestions(self) -> list[dict]:
        return list(self._site_mode_suggestions.values())

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

    def _get_auth_state_browser_entry_urls(self) -> list[str]:
        """返回浏览器获取 auth state 时的页面引导顺序"""
        login_url = self.provider_config.get_login_url()
        console_url = self.provider_config.get_console_personal_url()
        urls = []
        for url in [login_url, console_url]:
            if url and url not in urls:
                urls.append(url)
        return urls

    async def _wait_auth_state_page_stable(self, page) -> None:
        """等待 provider 页面基础脚本与运行时状态稳定"""
        await page.wait_for_timeout(3000)
        try:
            await page.wait_for_function('document.readyState === "complete"', timeout=10000)
        except Exception:
            await page.wait_for_timeout(3000)
        await page.wait_for_timeout(2000)

    async def _dismiss_known_login_modals(self, page) -> list[str]:
        """关闭会阻塞登录操作的已知公告弹窗"""
        dismissed_labels = []
        candidate_labels = [
            "Close Notice",
            "Close Today",
            "关闭公告",
            "今日关闭",
            "关闭提示",
            "关闭通知",
            "关闭",
        ]

        for _ in range(2):
            clicked_label = None
            for label in candidate_labels:
                button = page.get_by_role("button", name=label)
                try:
                    if await button.count():
                        await button.first.click()
                        await page.wait_for_timeout(1000)
                        dismissed_labels.append(label)
                        clicked_label = label
                        break
                except Exception as modal_err:
                    print(f"⚠️ {self.account_name}: Failed to dismiss modal button {label}: {modal_err}")

            if not clicked_label:
                break

        if dismissed_labels:
            if linuxdo_auth_debug_enabled():
                print(f"ℹ️ {self.account_name}: Dismissed blocking modal(s): {dismissed_labels}")

        return dismissed_labels

    async def _fetch_auth_state_in_browser_context(self, page) -> dict:
        """在当前浏览器上下文中直接请求 provider auth state 接口"""
        return await page.evaluate(
            """async (authStateUrl) => {
                try {
                    const response = await fetch(authStateUrl, { credentials: 'include' });
                    const rawText = await response.text();
                    let payload = null;
                    try {
                        payload = JSON.parse(rawText);
                    } catch (parseErr) {
                        payload = null;
                    }
                    return {
                        ok: response.ok,
                        status: response.status,
                        payload,
                        text: rawText.slice(0, 1000),
                    };
                } catch (e) {
                    return {
                        ok: false,
                        status: -1,
                        payload: null,
                        text: String(e),
                    };
                }
            }""",
            self.provider_config.get_auth_state_url(),
        )

    async def _load_linuxdo_storage_state_for_auth_browser(self) -> dict | None:
        """加载 LinuxDo 共享会话，用于注入 provider auth-state 浏览器上下文"""
        if self.linuxdo_session:
            shared_state = await self.linuxdo_session.get_storage_state()
            if shared_state:
                return shared_state

            shared_state_path = self.linuxdo_session.get_storage_state_path()
            if shared_state_path and os.path.exists(shared_state_path):
                try:
                    with open(shared_state_path, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except Exception as load_err:
                    print(f"⚠️ {self.account_name}: Failed to load shared LinuxDo storage state from file: {load_err}")

        linux_do = self.account_config.linux_do or {}
        username = linux_do.get("username", "")
        if not username:
            return None

        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        storage_state_path = os.path.join(self.storage_state_dir, f"linuxdo_{username_hash}_storage_state.json")
        if not os.path.exists(storage_state_path):
            return None

        try:
            with open(storage_state_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as load_err:
            print(f"⚠️ {self.account_name}: Failed to load LinuxDo storage state from {storage_state_path}: {load_err}")
            return None

    async def _click_linuxdo_continue_and_capture_auth_state(self, page, browser, entry_url: str | None = None) -> dict | None:
        """优先通过页面上的“使用 LinuxDO 继续”按钮引导到 connect 授权页"""
        text_patterns = [
            "使用 LinuxDO 继续",
            "使用 LinuxDo 继续",
            "Continue with LinuxDO",
            "Continue with LinuxDo",
        ]

        clicked = False
        for attempt in range(1, 3):
            if attempt > 1:
                if linuxdo_auth_debug_enabled():
                    print(f"ℹ️ {self.account_name}: LinuxDO continue entry not found, reopening bootstrap page and retrying once")
                target_url = entry_url or page.url
                try:
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                except Exception as nav_err:
                    print(f"⚠️ {self.account_name}: Failed to reopen bootstrap page for LinuxDO continue retry: {nav_err}")
                    return None
                if linuxdo_auth_debug_enabled():
                    print(f"ℹ️ {self.account_name}: Auth-state bootstrap current URL after retry navigation: {page.url}")
                await self._wait_auth_state_page_stable(page)
                await self._dismiss_known_login_modals(page)

            try:
                await page.wait_for_function(
                    """() => {
                        return Array.from(document.querySelectorAll('button, a, [role=\"button\"]')).some((el) => {
                            const text = (el.innerText || el.textContent || '').trim();
                            return /使用\\s*LinuxDO\\s*继续|使用\\s*LinuxDo\\s*继续|Continue with LinuxDO|Continue with LinuxDo/i.test(text);
                        });
                    }""",
                    timeout=5000,
                )
            except Exception:
                try:
                    visible_buttons = await page.evaluate(
                        """() => Array.from(document.querySelectorAll('button'))
                            .map((el) => (el.innerText || el.textContent || '').trim())
                            .filter(Boolean)
                            .slice(0, 10)"""
                    )
                    if visible_buttons:
                        if linuxdo_auth_debug_enabled():
                            print(f"ℹ️ {self.account_name}: Current visible button texts: {visible_buttons}")
                except Exception:
                    pass

            for text in text_patterns:
                try:
                    button_locator = page.get_by_role("button", name=text)
                    if await button_locator.count():
                        await button_locator.first.click()
                        clicked = True
                        if linuxdo_auth_debug_enabled():
                            print(f"ℹ️ {self.account_name}: Clicked LinuxDO continue button via role/name '{text}'")
                        break

                    text_button_locator = page.locator(f"button:has-text('{text}')")
                    if await text_button_locator.count():
                        await text_button_locator.first.click()
                        clicked = True
                        if linuxdo_auth_debug_enabled():
                            print(f"ℹ️ {self.account_name}: Clicked LinuxDO continue button via has-text '{text}'")
                        break

                    span_locator = page.locator("span.ml-3").filter(has_text=text)
                    if await span_locator.count():
                        target = span_locator.first.locator(
                            "xpath=ancestor::button[1] | ancestor::a[1] | ancestor::div[@role='button'][1]"
                        )
                        if await target.count():
                            await target.first.click()
                        else:
                            await span_locator.first.click()
                        clicked = True
                        if linuxdo_auth_debug_enabled():
                            print(f"ℹ️ {self.account_name}: Clicked LinuxDO continue entry via span text '{text}'")
                        break
                except Exception as click_err:
                    if linuxdo_auth_debug_enabled():
                        print(f"⚠️ {self.account_name}: Failed to click LinuxDO continue entry '{text}': {click_err}")

            if clicked:
                break

        if not clicked:
            return None

        try:
            await page.wait_for_url("**connect.linux.do/oauth2/authorize**", timeout=20000)
        except Exception:
            await page.wait_for_timeout(3000)

        current_url = page.url
        parsed = urlparse(current_url)
        query = parse_qs(parsed.query)
        state = query.get("state", [None])[0]

        if parsed.netloc == "connect.linux.do" and parsed.path.startswith("/oauth2/authorize") and state:
            cookies = await browser.cookies()
            if linuxdo_auth_debug_enabled():
                print(f"ℹ️ {self.account_name}: Captured auth state from LinuxDO continue entry: {state}")
            return {
                "success": True,
                "state": state,
                "cookies": cookies,
                "auth_state_via_browser": True,
                "auth_state_strategy": "linuxdo_continue",
            }

        if linuxdo_auth_debug_enabled():
            print(f"⚠️ {self.account_name}: LinuxDO continue entry did not land on connect authorize page: {current_url}")
        return None

    async def _click_linuxdo_continue_via_login_then_console(self, page, browser) -> dict | None:
        """当 console/personal 没有 LinuxDO 按钮时，先访问 login 再回 console/personal 重试"""
        login_url = self.provider_config.get_login_url()
        console_url = self.provider_config.get_console_personal_url()
        if not login_url or not console_url or login_url == console_url:
            return None

        if linuxdo_auth_debug_enabled():
            print(f"ℹ️ {self.account_name}: LinuxDO continue entry missing, trying login -> console/personal fallback")

        for step_label, target_url in [
            ("login", login_url),
            ("console/personal", console_url),
        ]:
            await page.goto(target_url, wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
            if linuxdo_auth_debug_enabled():
                print(f"ℹ️ {self.account_name}: Auth-state fallback step {step_label} current URL: {page.url}")
            await self._wait_auth_state_page_stable(page)
            await self._dismiss_known_login_modals(page)

        return await self._click_linuxdo_continue_and_capture_auth_state(page, browser, console_url)

    def _get_linuxdo_oauth_attempts(self) -> int:
        """返回 Linux.do OAuth 整链路最大尝试次数"""
        return 2

    def _should_run_auth_state_browser_headful(self) -> bool:
        """是否以有头模式运行 auth-state 调试浏览器"""
        return os.getenv("LINUXDO_AUTH_STATE_HEADFUL", "").strip().lower() in {"1", "true", "yes", "on"}

    def _should_force_ui_click_for_auth_state(self, force_ui_click: bool) -> bool:
        """判断当前站点是否应始终保留页面 LinuxDO 授权链路"""
        return force_ui_click

    def _should_retry_linuxdo_oauth_once(self, error_payload: dict | None) -> bool:
        """判断是否应重新获取 state 并再走一次 Linux.do OAuth"""
        if not isinstance(error_payload, dict):
            return False

        error_type = error_payload.get("error_type", "")
        retryable_error_types = {
            "linuxdo_signin_failed",
            "linuxdo_cloudflare_challenge",
            "linuxdo_high_load",
            "linuxdo_sso_provider_stuck",
            "linuxdo_redirect_login",
            "linuxdo_oauth_no_code",
            "linuxdo_allow_button_not_found",
            "linuxdo_auth_state_failed",
        }
        return error_type in retryable_error_types

    def _snapshot_linuxdo_authorize_state(self, cache_file_path: str) -> dict:
        """快照 Linux.do 授权前的预热态，便于失败后恢复干净状态"""
        snapshot = {
            'cache_file_path': cache_file_path,
            'cache_file_exists': bool(cache_file_path and os.path.exists(cache_file_path)),
            'cache_file_content': None,
            'shared_session_present': self.linuxdo_session is not None,
            'shared_is_logged_in': None,
            'shared_storage_state': None,
            'shared_storage_state_path': None,
            'shared_storage_state_file_exists': False,
            'shared_storage_state_file_content': None,
        }

        if snapshot['cache_file_exists']:
            with open(cache_file_path, 'r', encoding='utf-8') as f:
                snapshot['cache_file_content'] = f.read()

        if self.linuxdo_session is not None:
            snapshot['shared_is_logged_in'] = getattr(self.linuxdo_session, 'is_logged_in', False)
            snapshot['shared_storage_state'] = copy.deepcopy(getattr(self.linuxdo_session, '_storage_state', None))

            try:
                shared_path = self.linuxdo_session.get_storage_state_path()
            except Exception:
                shared_path = None

            snapshot['shared_storage_state_path'] = shared_path
            if shared_path and os.path.exists(shared_path):
                snapshot['shared_storage_state_file_exists'] = True
                with open(shared_path, 'r', encoding='utf-8') as f:
                    snapshot['shared_storage_state_file_content'] = f.read()

        return snapshot

    def _restore_linuxdo_authorize_state(self, snapshot: dict) -> None:
        """恢复 Linux.do 授权前快照，丢弃失败尝试遗留状态"""
        cache_file_path = snapshot.get('cache_file_path')
        if cache_file_path:
            if snapshot.get('cache_file_exists'):
                with open(cache_file_path, 'w', encoding='utf-8') as f:
                    f.write(snapshot.get('cache_file_content') or '')
            elif os.path.exists(cache_file_path):
                os.remove(cache_file_path)

        if self.linuxdo_session is None or not snapshot.get('shared_session_present'):
            return

        self.linuxdo_session.is_logged_in = bool(snapshot.get('shared_is_logged_in'))
        self.linuxdo_session._storage_state = copy.deepcopy(snapshot.get('shared_storage_state'))

        shared_path = snapshot.get('shared_storage_state_path')
        if not shared_path:
            return

        if snapshot.get('shared_storage_state_file_exists'):
            with open(shared_path, 'w', encoding='utf-8') as f:
                f.write(snapshot.get('shared_storage_state_file_content') or '')
        elif os.path.exists(shared_path):
            os.remove(shared_path)

    async def get_auth_state_with_browser(self, force_ui_click: bool = False) -> dict:
        """使用 Camoufox 获取认证 URL 和 cookies

        Args:
            force_ui_click: 是否跳过直接 fetch state，强制改走页面 LinuxDO 按钮链路

        Returns:
            包含 success、url、cookies 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get auth state (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )
        effective_force_ui_click = self._should_force_ui_click_for_auth_state(force_ui_click)

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_auth_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            headful_debug = self._should_run_auth_state_browser_headful()
            if headful_debug:
                print(f"ℹ️ {self.account_name}: Auth-state browser debug is running in headed mode")
            linuxdo_storage_state = await self._load_linuxdo_storage_state_for_auth_browser()
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=not headful_debug,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
            ) as browser:
                page = await browser.new_page()

                try:
                    if linuxdo_storage_state and linuxdo_storage_state.get("cookies"):
                        await browser.add_cookies(linuxdo_storage_state.get("cookies", []))
                        if linuxdo_auth_debug_enabled():
                            print(
                                f"ℹ️ {self.account_name}: Injected {len(linuxdo_storage_state.get('cookies', []))} "
                                "LinuxDo cookie(s) into auth-state browser"
                            )

                    last_response = None
                    last_error = None
                    entry_urls = self._get_auth_state_browser_entry_urls()

                    for index, entry_url in enumerate(entry_urls, start=1):
                        try:
                            print(
                                f"ℹ️ {self.account_name}: Opening auth-state bootstrap page "
                                f"{index}/{len(entry_urls)} -> {entry_url}"
                            )
                            await page.goto(entry_url, wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                            if linuxdo_auth_debug_enabled():
                                print(f"ℹ️ {self.account_name}: Auth-state bootstrap current URL: {page.url}")
                            await self._wait_auth_state_page_stable(page)
                            await self._dismiss_known_login_modals(page)

                            if self.provider_config.aliyun_captcha:
                                captcha_check = await aliyun_captcha_check(page, self.account_name)
                                if captcha_check:
                                    await page.wait_for_timeout(3000)

                            # 默认优先在当前页面内直接 fetch auth state，减少对前端按钮文案/DOM 的依赖。
                            # 如果上一轮已经拿到 state 但 authorize 仍失败，外层会将 force_ui_click 置为 True，
                            # 此时本轮跳过 fetch，直接改走页面 LinuxDO 按钮链路。
                            # anyrouter 需要保留原有页面授权，因此也会强制走按钮链路。
                            if not effective_force_ui_click:
                                response = await self._fetch_auth_state_in_browser_context(page)
                                last_response = response
                                response_payload = response.get("payload") or {}

                                if response_payload.get("success") and "data" in response_payload:
                                    cookies = await browser.cookies()
                                    return {
                                        "success": True,
                                        "state": response_payload.get("data"),
                                        "cookies": cookies,
                                        "auth_state_via_browser": True,
                                        "auth_state_strategy": "fetch",
                                    }

                                if linuxdo_auth_debug_enabled():
                                    print(
                                        f"⚠️ {self.account_name}: Browser auth state fetch via {entry_url} failed: "
                                        f"status={response.get('status')}, text={response.get('text')}"
                                    )
                            else:
                                if linuxdo_auth_debug_enabled():
                                    print(
                                        f"ℹ️ {self.account_name}: Force LinuxDO continue button flow for auth state retry via "
                                        f"{entry_url}"
                                    )

                            clicked_auth_state = await self._click_linuxdo_continue_and_capture_auth_state(
                                page, browser, entry_url
                            )
                            if not clicked_auth_state:
                                clicked_auth_state = await self._click_linuxdo_continue_via_login_then_console(
                                    page, browser
                                )
                            if clicked_auth_state:
                                return clicked_auth_state
                        except Exception as entry_err:
                            last_error = f"{entry_url}: {entry_err}"
                            print(f"⚠️ {self.account_name}: Auth-state bootstrap via {entry_url} failed: {entry_err}")
                            continue

                    if last_error and last_response is None:
                        error_detail = last_error
                    else:
                        error_detail = json.dumps(last_response, ensure_ascii=False, indent=2)
                    return {
                        "success": False,
                        "error": f"Failed to get state, \n{error_detail}",
                    }

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
        force_browser_ui_click: bool = False,
    ) -> dict:
        """获取认证状态"""
        async def fallback_to_browser(reason: str) -> dict:
            print(f"⚠️ {self.account_name}: HTTP auth state failed ({reason}), fallback to browser auth state")
            auth_result = await self.get_auth_state_with_browser(force_ui_click=force_browser_ui_click)
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
                            http_only = (
                                cookie.has_nonstandard_attr("HttpOnly")
                                or cookie.has_nonstandard_attr("httponly")
                            )
                            same_site = (
                                cookie.get_nonstandard_attr("SameSite")
                                or cookie.get_nonstandard_attr("samesite")
                                or "Lax"
                            )
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
                async def extract_callback_state() -> dict:
                    return await page.evaluate(
                        f"""async () => {{
                            const result = {{
                                apiUser: null,
                                responseJson: null,
                                errorMsg: '',
                                storageKeys: [],
                                userInfoStatus: null,
                                userInfoError: '',
                            }};

                            const pickId = (value) => {{
                                if (!value || typeof value !== 'object') return null;
                                if (value.id !== undefined && value.id !== null && value.id !== '') return value.id;
                                for (const key of ['data', 'user', 'profile', 'currentUser']) {{
                                    const nested = value[key];
                                    if (nested && typeof nested === 'object') {{
                                        const nestedId = pickId(nested);
                                        if (nestedId !== null && nestedId !== undefined && nestedId !== '') {{
                                            return nestedId;
                                        }}
                                    }}
                                }}
                                return null;
                            }};

                            try {{
                                const text = document.body ? (document.body.innerText || '').trim() : '';
                                if (text) {{
                                    try {{
                                        const parsed = JSON.parse(text);
                                        result.responseJson = parsed;
                                        result.errorMsg = parsed?.message || parsed?.error || '';
                                        const parsedId = pickId(parsed);
                                        if (parsedId !== null && parsedId !== undefined && parsedId !== '') {{
                                            result.apiUser = parsedId;
                                        }}
                                    }} catch (e) {{}}
                                }}
                            }} catch (e) {{}}

                            for (const key of ['user', 'status', 'userInfo', 'userinfo']) {{
                                try {{
                                    const raw = localStorage.getItem(key);
                                    if (!raw) continue;
                                    result.storageKeys.push(key);
                                    const parsed = JSON.parse(raw);
                                    const storageId = pickId(parsed);
                                    if (storageId !== null && storageId !== undefined && storageId !== '') {{
                                        result.apiUser = storageId;
                                        break;
                                    }}
                                }} catch (e) {{}}
                            }}

                            try {{
                                const sessionResponse = await fetch('{self.provider_config.get_user_info_url()}', {{
                                    credentials: 'include'
                                }});
                                result.userInfoStatus = sessionResponse.status;
                                const text = await sessionResponse.text();
                                try {{
                                    const parsed = JSON.parse(text);
                                    const sessionUserId = pickId(parsed);
                                    if (sessionUserId !== null && sessionUserId !== undefined && sessionUserId !== '') {{
                                        result.apiUser = sessionUserId;
                                    }}
                                    if (!result.errorMsg) {{
                                        result.errorMsg = parsed?.message || parsed?.error || '';
                                    }}
                                }} catch (e) {{}}
                            }} catch (e) {{
                                result.userInfoError = e.message || String(e);
                            }}

                            if (result.apiUser !== null && result.apiUser !== undefined && result.apiUser !== '') {{
                                try {{
                                    const response = await fetch('{self.provider_config.get_user_info_url()}', {{
                                        headers: {{
                                            '{self.provider_config.api_user_key}': String(result.apiUser)
                                        }},
                                        credentials: 'include'
                                    }});
                                    result.userInfoStatus = response.status;
                                    const text = await response.text();
                                    try {{
                                        const parsed = JSON.parse(text);
                                        const userInfoId = pickId(parsed);
                                        if (userInfoId !== null && userInfoId !== undefined && userInfoId !== '') {{
                                            result.apiUser = userInfoId;
                                        }}
                                        if (!result.errorMsg) {{
                                            result.errorMsg = parsed?.message || parsed?.error || '';
                                        }}
                                    }} catch (e) {{}}
                                }} catch (e) {{
                                    result.userInfoError = e.message || String(e);
                                }}
                            }}

                            return result;
                        }}"""
                    )

                async def collect_success_result(source: str) -> dict | None:
                    probe_result = await extract_callback_state()
                    api_user = probe_result.get("apiUser")
                    if api_user:
                        restore_cookies = await page.context.cookies()
                        user_cookies = filter_cookies(restore_cookies, self.provider_config.origin)
                        print(f"✅ {self.account_name}: Browser callback fallback got api_user from {source}: {api_user}")
                        return {
                            "success": True,
                            "api_user": api_user,
                            "cookies": user_cookies,
                        }

                    response_json = probe_result.get("responseJson")
                    error_msg = probe_result.get("errorMsg")
                    if isinstance(response_json, dict) and error_msg:
                        print(f"⚠️ {self.account_name}: Browser callback fallback returned structured error: {error_msg}")
                        return {"success": False, "error": error_msg}

                    return None

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

                direct_result = await collect_success_result("callback page")
                if direct_result:
                    return direct_result

                probe_urls = []
                for probe_url in [
                    self.provider_config.origin,
                    self.provider_config.get_console_personal_url(),
                    self.provider_config.get_login_url(),
                ]:
                    if probe_url and probe_url not in probe_urls:
                        probe_urls.append(probe_url)

                for probe_url in probe_urls:
                    try:
                        print(f"ℹ️ {self.account_name}: Callback fallback probing page -> {probe_url}")
                        await page.goto(probe_url, wait_until="networkidle", timeout=TIMEOUT_PAGE_LOAD)
                        await page.wait_for_timeout(3000)
                    except Exception as probe_err:
                        print(f"⚠️ {self.account_name}: Callback fallback probe failed for {probe_url}: {probe_err}")
                        continue

                    probe_result = await collect_success_result(probe_url)
                    if probe_result:
                        return probe_result

                await save_page_content_to_file(page, "linuxdo_callback_browser_fallback_failed", self.account_name, prefix="linuxdo")
                await take_screenshot(page, "linuxdo_callback_browser_fallback_failed", self.account_name)
                return {"success": False, "error": "Browser callback fallback could not extract api_user"}
            finally:
                await page.close()
                await context.close()

    async def complete_linuxdo_callback_with_http_frontend(
        self,
        frontend_callback_url: str,
        api_callback_url: str,
        headers: dict,
        auth_cookies: list[dict] | None = None,
    ) -> dict:
        """先以纯 HTTP 访问前端 callback，再调用 API callback，兼容依赖前端落 provider session 的站点"""
        print(f"ℹ️ {self.account_name}: Trying frontend-first HTTP callback flow")
        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config, follow_redirects=True)
        try:
            if auth_cookies:
                for cookie_dict in auth_cookies:
                    cookie_name = cookie_dict.get("name")
                    cookie_value = cookie_dict.get("value")
                    cookie_domain = cookie_dict.get("domain") or urlparse(self.provider_config.origin).netloc
                    cookie_path = cookie_dict.get("path") or "/"
                    if cookie_name and cookie_value is not None:
                        client.cookies.set(cookie_name, cookie_value, domain=cookie_domain, path=cookie_path)

            frontend_response = client.get(frontend_callback_url, headers=headers, timeout=30)
            print(f"ℹ️ {self.account_name}: Frontend callback HTTP {frontend_response.status_code}")
            api_response = client.get(api_callback_url, headers=headers, timeout=30)
            if api_response.status_code != 200:
                return {"success": False, "error": f"Frontend-first API callback HTTP {api_response.status_code}"}

            json_data = response_resolve(api_response, "linuxdo_oauth_callback_frontend_first", self.account_name)
            if not json_data or not json_data.get("success"):
                error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                return {"success": False, "error": f"Frontend-first API callback failed: {error_msg}"}

            user_data = json_data.get("data", {})
            api_user = user_data.get("id")
            if not api_user:
                return {"success": False, "error": "Frontend-first API callback returned no user ID"}

            user_cookies = {cookie.name: cookie.value for cookie in api_response.cookies.jar}
            if not user_cookies:
                user_cookies = {cookie.name: cookie.value for cookie in client.cookies.jar if urlparse(self.provider_config.origin).netloc in cookie.domain}

            print(f"✅ {self.account_name}: Frontend-first HTTP callback got api_user: {api_user}")
            return {
                "success": True,
                "api_user": api_user,
                "cookies": user_cookies,
            }
        finally:
            client.close()

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
                    browser_checkin_status = None
                    browser_checkin_error = None
                    browser_checkin_message = ""

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
                            browser_checkin_message = checkin_response.get("message", "")
                            if checkin_response.get("success"):
                                browser_checkin_status = "success"
                                print(f"✅ {self.account_name}: Checkin successful - {browser_checkin_message}")
                            elif "已签到" in browser_checkin_message or "already" in browser_checkin_message.lower():
                                browser_checkin_status = "already_checked"
                                print(f"ℹ️ {self.account_name}: Already checked in - {browser_checkin_message}")
                            else:
                                browser_checkin_status = "failed"
                                browser_checkin_error = browser_checkin_message or "Browser checkin failed"
                                print(f"⚠️ {self.account_name}: Checkin response - {browser_checkin_message}")
                        else:
                            browser_checkin_status = "failed"
                            browser_checkin_error = "Browser checkin returned empty response"

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
                        result = {
                            "success": True,
                            "quota": quota,
                            "used_quota": used_quota,
                            "bonus_quota": bonus_quota,
                            "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                        }
                        if do_checkin:
                            result["checkin_status"] = browser_checkin_status or "failed"
                            result["checkin_message"] = browser_checkin_message
                            if browser_checkin_error:
                                result["checkin_error"] = browser_checkin_error
                        return result

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

        sign_in_url = self.provider_config.get_sign_in_url(api_user)
        checkin_headers = headers.copy()
        checkin_headers.update({"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"})
        if sign_in_url and sign_in_url.endswith("/api/user/checkin"):
            checkin_headers["Referer"] = f"{self.provider_config.origin}/console/topup"

        # 某些非标准站点（如 wong）前端会先 GET /api/user/checkin 获取 checked_in 状态
        if sign_in_url and sign_in_url.endswith("/api/user/checkin"):
            try:
                status_response = client.get(sign_in_url, headers=checkin_headers, timeout=30)
                print(f"📨 {self.account_name}: Check-in status response code {status_response.status_code}")
                if status_response.status_code in [200, 400]:
                    status_json = response_resolve(status_response, "execute_check_in_status", self.account_name)
                    if status_json and status_json.get("success"):
                        status_data = status_json.get("data", {})
                        if isinstance(status_data, dict) and status_data.get("checked_in"):
                            print(f"ℹ️ {self.account_name}: Already checked in according to /api/user/checkin status")
                            return True, ""
            except Exception as status_err:
                print(f"⚠️ {self.account_name}: Failed to get check-in status before POST: {status_err}")

        response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

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

    def should_use_browser_manual_check_in(self, api_user: str | int) -> bool:
        """判断是否应优先使用浏览器版手动签到"""
        return False

    async def execute_check_in_with_browser(
        self,
        auth_cookies: list[dict],
        api_user: str | int,
        page_path: str = "/console/topup",
    ) -> tuple[bool, str]:
        """使用浏览器页面上下文执行手动签到，更贴近前端实际行为"""
        print(
            f"ℹ️ {self.account_name}: Executing browser-based manual check-in at {page_path} "
            f"(using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        sign_in_url = self.provider_config.get_sign_in_url(api_user)
        if not sign_in_url:
            return False, "No sign-in URL configured"

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_manual_checkin_") as tmp_dir:
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

                if auth_cookies:
                    await browser.add_cookies(auth_cookies)

                try:
                    await page.goto(f"{self.provider_config.origin}{page_path}", wait_until="networkidle", timeout=60000)
                    await page.wait_for_timeout(2000)

                    result = await page.evaluate(
                        f"""async () => {{
                            const headers = {{
                                'Content-Type': 'application/json',
                                'X-Requested-With': 'XMLHttpRequest',
                                '{self.provider_config.api_user_key}': '{api_user}',
                            }};

                            try {{
                                const statusResp = await fetch('{sign_in_url}', {{
                                    method: 'GET',
                                    headers,
                                    credentials: 'include'
                                }});
                                const statusData = await statusResp.json().catch(() => null);
                                if (statusData && statusData.success && statusData.data && statusData.data.checked_in) {{
                                    return {{ success: true, already_checked: true, message: '今天已经签到过啦' }};
                                }}
                            }} catch (e) {{
                                // ignore status failure, continue POST
                            }}

                            try {{
                                const resp = await fetch('{sign_in_url}', {{
                                    method: 'POST',
                                    headers,
                                    credentials: 'include'
                                }});
                                const data = await resp.json().catch(() => null);
                                return {{
                                    success: !!(data && (data.success || data.ret === 1 || data.code === 0)),
                                    message: data ? (data.message || data.msg || '') : `HTTP ${{resp.status}}`,
                                    raw: data,
                                    status: resp.status
                                }};
                            }} catch (e) {{
                                return {{ success: false, message: e.message }};
                            }}
                        }}"""
                    )

                    message = result.get("message", "")
                    if result.get("success") or "已签到" in message or "今天已经签到" in message:
                        print(f"✅ {self.account_name}: Browser manual check-in successful - {message}")
                        return True, ""

                    print(f"❌ {self.account_name}: Browser manual check-in failed - {message}")
                    return False, message or "Browser manual check-in failed"
                except Exception as e:
                    print(f"❌ {self.account_name}: Browser manual check-in error: {e}")
                    await take_screenshot(page, "manual_checkin_browser_error", self.account_name)
                    return False, f"Browser manual check-in error: {e}"
                finally:
                    await page.close()

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

    async def validate_provider_session(self, cookies: dict, api_user: str | int) -> dict:
        """验证站点 session 缓存是否仍可用于已登录操作"""
        print(f"ℹ️ {self.account_name}: Validating cached provider session before reuse")

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(cookies)

            headers = {
                "User-Agent": get_random_user_agent(),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": SAFE_HTTP_ACCEPT_ENCODING,
                "Referer": self.provider_config.get_login_url(),
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                self.provider_config.api_user_key: f"{api_user}",
            }

            if self.provider_config.name == "anyrouter":
                user_info = await self.get_user_info(client, headers)
                if not (user_info and user_info.get("success")):
                    print(f"⚠️ {self.account_name}: Cached anyrouter session HTTP validation failed, fallback to browser")
                    auth_cookies_list = []
                    parsed_domain = urlparse(self.provider_config.origin).netloc
                    for name, value in cookies.items():
                        auth_cookies_list.append({
                            "name": name,
                            "value": value,
                            "domain": parsed_domain,
                            "path": "/",
                        })
                    user_info = await self.get_user_info_with_browser(auth_cookies_list, api_user, do_checkin=False)
            elif self.provider_config.needs_waf_cookies():
                auth_cookies_list = []
                parsed_domain = urlparse(self.provider_config.origin).netloc
                for name, value in cookies.items():
                    auth_cookies_list.append({
                        "name": name,
                        "value": value,
                        "domain": parsed_domain,
                        "path": "/",
                    })
                user_info = await self.get_user_info_with_browser(auth_cookies_list, api_user, do_checkin=False)
            else:
                user_info = await self.get_user_info(client, headers)

            if user_info and user_info.get("success"):
                print(f"✅ {self.account_name}: Cached provider session is reusable")
                return {"success": True, "user_info": user_info}

            error_msg = user_info.get("error", "Cached provider session validation failed") if user_info else "No user info available"
            print(f"⚠️ {self.account_name}: Cached provider session is not reusable - {error_msg}")
            return {"success": False, "error": error_msg}
        except Exception as e:
            error_msg = f"Cached provider session validation error: {e}"
            print(f"⚠️ {self.account_name}: {error_msg}")
            return {"success": False, "error": error_msg}
        finally:
            client.close()

    async def check_in_with_cookies(self, cookies: dict, api_user: str | int) -> tuple[bool, dict]:
        """使用已有 cookies 执行签到操作"""
        print(
            f"ℹ️ {self.account_name}: Executing check-in with existing cookies (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(cookies)
            runtime_modes = self._get_active_linuxdo_runtime_modes()
            prefer_browser_first_checkin = should_prefer_browser_first_newapi_checkin(
                self.provider_config,
                runtime_modes,
            )
            dynamic_browser_checkin_reason = ''

            headers = {
                "User-Agent": get_random_user_agent(),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": SAFE_HTTP_ACCEPT_ENCODING,
                "Referer": self.provider_config.get_login_url(),
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                self.provider_config.api_user_key: f"{api_user}",
            }

            checkin_required = bool(self.account_config.checkin)
            checkin_status = None
            checkin_error = None
            checkin_message = ""

            if self.provider_config.needs_manual_check_in():
                sign_in_url = self.provider_config.get_sign_in_url(api_user) or ""
                if self.should_use_browser_manual_check_in(api_user):
                    print(f"ℹ️ {self.account_name}: Using browser manual check-in flow")
                    auth_cookies_list = []
                    parsed_domain = urlparse(self.provider_config.origin).netloc
                    for name, value in cookies.items():
                        auth_cookies_list.append({
                            "name": name,
                            "value": value,
                            "domain": parsed_domain,
                            "path": "/",
                        })
                    browser_success, browser_error = await self.execute_check_in_with_browser(
                        auth_cookies_list,
                        api_user,
                        page_path="/console/topup",
                    )
                    if not browser_success:
                        return False, {"error": browser_error or "Check-in failed"}
                else:
                    success, error_msg = self.execute_check_in(client, headers, api_user)
                    if not success:
                        if sign_in_url.endswith("/api/user/checkin"):
                            print(f"⚠️ {self.account_name}: HTTP manual check-in failed, trying browser manual check-in fallback")
                            auth_cookies_list = []
                            parsed_domain = urlparse(self.provider_config.origin).netloc
                            for name, value in cookies.items():
                                auth_cookies_list.append({
                                    "name": name,
                                    "value": value,
                                    "domain": parsed_domain,
                                    "path": "/",
                                })
                            browser_success, browser_error = await self.execute_check_in_with_browser(
                                auth_cookies_list,
                                api_user,
                                page_path="/console/topup",
                            )
                            if not browser_success:
                                return False, {"error": browser_error or error_msg or "Check-in failed"}
                        else:
                            return False, {"error": error_msg or "Check-in failed"}
            else:
                print(f"ℹ️ {self.account_name}: Check-in completed automatically (triggered by user info request)")

            # 如果账号配置启用了 New-API 通用签到功能
            # 对于 WAF 模式或 Turnstile 模式，签到将在浏览器中执行，这里跳过
            do_browser_checkin = False
            checkin_reward = None  # 保存签到奖励信息
            if self.account_config.checkin:
                if prefer_browser_first_checkin:
                    print(
                        f"ℹ️ {self.account_name}: Runtime mode prefers browser-first New-API checkin "
                        f"({runtime_modes.get('checkin_reason', 'default browser-first')})"
                    )
                    do_browser_checkin = True
                elif self.provider_config.needs_waf_cookies():
                    if has_provider_bypass_cookies(cookies):
                        print(f"ℹ️ {self.account_name}: Reusable WAF cookies detected, trying HTTP New-API checkin first")
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
                            checkin_status = "already_checked" if checkin_result.get("already_checked") else "success"
                            checkin_message = checkin_result.get("message", "")
                            checkin_reward = checkin_result.get("reward")
                            if checkin_result.get("already_checked"):
                                checkin_reward = None
                        else:
                            error_msg = checkin_result.get("error", "New-API checkin failed")
                            print(f"❌ {self.account_name}: New-API checkin failed - {error_msg}")
                            if should_retry_newapi_checkin_in_browser(error_msg):
                                print(
                                    f"⚠️ {self.account_name}: HTTP New-API checkin looks recoverable, "
                                    "will fallback to browser mode in this run"
                                )
                                do_browser_checkin = True
                                dynamic_browser_checkin_reason = error_msg
                            else:
                                checkin_status = "failed"
                                checkin_error = error_msg
                                checkin_message = error_msg
                    else:
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
                        checkin_status = "already_checked" if checkin_result.get("already_checked") else "success"
                        checkin_message = checkin_result.get("message", "")
                        checkin_reward = checkin_result.get("reward")
                        if checkin_result.get("already_checked"):
                            checkin_reward = None
                    else:
                        error_msg = checkin_result.get("error", "New-API checkin failed")
                        print(f"❌ {self.account_name}: New-API checkin failed - {error_msg}")
                        checkin_status = "failed"
                        checkin_error = error_msg
                        checkin_message = error_msg
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
                        checkin_status = "already_checked" if checkin_result.get("already_checked") else "success"
                        checkin_message = checkin_result.get("message", "")
                        checkin_reward = checkin_result.get("reward")
                        if checkin_result.get("already_checked"):
                            checkin_reward = None  # 已签到不显示奖励
                    else:
                        error_msg = checkin_result.get("error", "New-API checkin failed")
                        print(f"❌ {self.account_name}: New-API checkin failed - {error_msg}")
                        if self.provider_config.name != "anyrouter" and should_retry_newapi_checkin_in_browser(error_msg):
                            print(
                                f"⚠️ {self.account_name}: New-API HTTP checkin failed, "
                                "will fallback to browser mode in this run"
                            )
                            do_browser_checkin = True
                            dynamic_browser_checkin_reason = error_msg
                        else:
                            checkin_status = "failed"
                            checkin_error = error_msg
                            checkin_message = error_msg

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
                if has_provider_bypass_cookies(cookies) and not do_browser_checkin:
                    print(f"ℹ️ {self.account_name}: Reusable WAF cookies detected, trying HTTP user info first")
                    user_info = await self.get_user_info(client, headers)
                    if not (user_info and user_info.get("success")):
                        print(f"⚠️ {self.account_name}: HTTP user info failed for WAF site, fallback to browser")
                        auth_cookies_list = []
                        parsed_domain = urlparse(self.provider_config.origin).netloc
                        for name, value in cookies.items():
                            auth_cookies_list.append({
                                "name": name,
                                "value": value,
                                "domain": parsed_domain,
                                "path": "/",
                            })
                        user_info = await self.get_user_info_with_browser(
                            auth_cookies_list,
                            api_user,
                            do_checkin=do_browser_checkin,
                        )
                else:
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
                if do_browser_checkin or not (user_info and user_info.get("success")):
                    fallback_reason = "check-in fallback" if do_browser_checkin else "HTTP user info failed"
                    print(f"⚠️ {self.account_name}: {fallback_reason}, trying browser mode")
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
            if user_info and user_info.get("success"):
                if do_browser_checkin and checkin_required:
                    browser_checkin_status = user_info.get("checkin_status")
                    if browser_checkin_status in {"success", "already_checked"}:
                        checkin_status = browser_checkin_status
                        checkin_message = user_info.get("checkin_message", "")
                    else:
                        checkin_status = "failed"
                        checkin_error = user_info.get("checkin_error") or user_info.get("checkin_message") or "Browser checkin failed"
                        checkin_message = user_info.get("checkin_message", checkin_error or "")

                if do_browser_checkin:
                    if dynamic_browser_checkin_reason:
                        print(f"ℹ️ {self.account_name}: Promoting runtime mode to browser-first New-API checkin")
                        self._mark_active_browser_first_checkin(dynamic_browser_checkin_reason)
                    elif prefer_browser_first_checkin:
                        self._mark_active_browser_first_checkin(
                            runtime_modes.get('checkin_reason', 'browser_first_runtime_refresh')
                        )

                if checkin_required and checkin_status not in {"success", "already_checked"}:
                    failure_msg = checkin_error or checkin_message or "Check-in did not complete successfully"
                    print(f"❌ {self.account_name}: Final check-in status is not successful - {failure_msg}")
                    return False, {
                        "error_type": "checkin_not_successful",
                        "error_summary": failure_msg,
                        "error_detail": failure_msg,
                        "error": failure_msg,
                    }

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
        self._active_linuxdo_username_hash = None
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
                "Accept-Encoding": SAFE_HTTP_ACCEPT_ENCODING,
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

        if self.provider_config.needs_waf_cookies() and not waf_cookies:
            print(f"ℹ️ {self.account_name}: Deferring WAF cookie bootstrap until provider session/cache really needs it")

        # 生成缓存文件路径
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        self._active_linuxdo_username_hash = username_hash
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

            if (
                should_prefetch_waf_before_cached_session_use(self.provider_config)
                and not has_provider_bypass_cookies(merged_cookies)
            ):
                print(f"ℹ️ {self.account_name}: Prefetching WAF cookies before cached provider session reuse")
                prefetched_waf_cookies = await self.get_waf_cookies_with_browser() or {}
                if prefetched_waf_cookies:
                    merged_cookies = {**prefetched_waf_cookies, **cached_cookies}
                else:
                    print(f"⚠️ {self.account_name}: WAF prefetch before cache reuse failed, continue with existing cookies")

            if login_only:
                validation_result = await self.validate_provider_session(merged_cookies, cached_api_user)
                if validation_result.get("success"):
                    if is_stale_cache:
                        _save_provider_session_cache(provider_cache_path, cached_cookies, cached_api_user)
                        print(f"✅ {self.account_name}: Stale provider session cache is still valid, timestamp refreshed")
                    return True, {"cookies": merged_cookies, "api_user": cached_api_user}

                error_msg = validation_result.get("error", "Cached provider session validation failed")
                if should_rebuild_provider_cache(self.provider_config.name, error_msg):
                    print(
                        f"⚠️ {self.account_name}: Cached provider session is invalid for login-only flow, "
                        "clearing cache and re-authorizing with LinuxDo prewarmed session"
                    )
                    try:
                        os.remove(provider_cache_path)
                    except Exception:
                        pass
                else:
                    return False, {"error": error_msg}

            # 使用缓存的 cookies 执行签到
            else:
                if should_validate_provider_session_before_reuse(self.provider_config):
                    print(f"ℹ️ {self.account_name}: Validating cached provider session before reuse for this host")
                    validation_result = await self.validate_provider_session(merged_cookies, cached_api_user)
                    if not validation_result.get("success"):
                        error_msg = validation_result.get("error", "Cached provider session validation failed")
                        if should_rebuild_provider_cache(self.provider_config.name, error_msg):
                            print(
                                f"⚠️ {self.account_name}: Cached provider session is invalid before reuse, "
                                "clearing cache and re-authorizing with LinuxDo prewarmed session"
                            )
                            try:
                                os.remove(provider_cache_path)
                            except Exception:
                                pass
                        else:
                            return False, {"error": error_msg}
                    else:
                        print(f"✅ {self.account_name}: Cached provider session validated before reuse")

                success, result = await self.check_in_with_cookies(merged_cookies, cached_api_user)

                # 如果签到失败（可能是 session 过期或 WAF 挑战），清除缓存并重新登录
                if not success and "error" in result:
                    error_msg = result.get("error", "").lower()
                    if should_rebuild_provider_cache(self.provider_config.name, error_msg):
                        if (
                            "http 401" in error_msg
                            or "未登录且未提供 access token" in error_msg
                            or "failed to get user info: http 401" in error_msg
                        ) and (self.provider_config.cache_reuse_mode or '').strip().lower() != 'validate-before-use':
                            self._suggest_site_mode(
                                'cache_reuse_mode',
                                'validate-before-use',
                                'cached session reuse hit 401/unauthorized',
                            )
                        if (
                            self.provider_config.needs_waf_cookies()
                            and ("invalid response format" in error_msg or "text/html" in error_msg or "html" in error_msg)
                            and (self.provider_config.cache_waf_mode or '').strip().lower() != 'prefetch-before-reuse'
                        ):
                            self._suggest_site_mode(
                                'cache_waf_mode',
                                'prefetch-before-reuse',
                                'cached session reuse hit WAF/HTML response',
                            )
                        print(
                            f"⚠️ {self.account_name}: Cached provider session may be expired or blocked, "
                            "clearing cache and re-authorizing with LinuxDo prewarmed session"
                        )
                        try:
                            os.remove(provider_cache_path)
                        except Exception:
                            pass
                        if self.provider_config.name == "anyrouter":
                            from utils.linuxdo_session import LinuxDoSessionManager

                            print(f"ℹ️ {self.account_name}: anyrouter cache invalid, forcing LinuxDo shared session rebuild")
                            oauth_probes = None
                            if self.provider_config.linuxdo_client_id:
                                oauth_probes = [{
                                    "label": self.provider_config.name,
                                    "client_id": self.provider_config.linuxdo_client_id,
                                    "provider_origin": self.provider_config.origin,
                                }]
                            refreshed_session = await LinuxDoSessionManager.get_session(
                                username,
                                password,
                                proxy=self.camoufox_proxy_config,
                                auto_login=True,
                                oauth_probes=oauth_probes,
                            )
                            shared_state_path = refreshed_session.get_storage_state_path()
                            if not getattr(refreshed_session, "is_logged_in", False) and not (
                                shared_state_path and os.path.exists(shared_state_path)
                            ):
                                return False, {
                                    "error": (
                                        "anyrouter provider cache invalid and LinuxDo shared session is not warmed. "
                                        "Please run `uv run python prepare_linuxdo_session.py` first"
                                    )
                                }
                            if not getattr(refreshed_session, "is_logged_in", False):
                                print(
                                    f"ℹ️ {self.account_name}: LinuxDo shared session is not confirmed by prewarm, "
                                    "but storage state file still exists, continue OAuth re-authorization"
                                )
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

        if self.provider_config.needs_waf_cookies() and not waf_cookies:
            waf_cookies = await self.get_waf_cookies_with_browser() or {}
            if waf_cookies:
                print(f"✅ {self.account_name}: Deferred WAF cookies obtained before OAuth flow")
            else:
                print(f"⚠️ {self.account_name}: Deferred WAF cookie bootstrap failed, continue with auth-state browser flow")

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(waf_cookies)

            headers = {
                "User-Agent": get_random_user_agent(),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": SAFE_HTTP_ACCEPT_ENCODING,
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

            max_oauth_attempts = self._get_linuxdo_oauth_attempts()
            linuxdo_state_snapshot = self._snapshot_linuxdo_authorize_state(cache_file_path)
            auth_state_result = None
            success = False
            result_data = {}
            force_browser_ui_click = False

            for oauth_attempt in range(1, max_oauth_attempts + 1):
                if oauth_attempt > 1:
                    print(
                        f"⚠️ {self.account_name}: Linux.do OAuth authorization failed previously, "
                        f"restarting full state+authorize flow ({oauth_attempt}/{max_oauth_attempts})"
                    )
                    self._restore_linuxdo_authorize_state(linuxdo_state_snapshot)
                    await asyncio.sleep(2)

                client.cookies.clear()
                client.cookies.update(waf_cookies)
                print(f"ℹ️ {self.account_name}: Reset provider-side cookies before OAuth attempt {oauth_attempt}")

                # 获取 OAuth 认证状态
                # 除 anyrouter 外，WAF 站点也先尝试 HTTP /api/oauth/state，命中 403/HTML 后再回退浏览器
                if self.provider_config.needs_waf_cookies() and self.provider_config.name == "anyrouter":
                    print(f"ℹ️ {self.account_name}: Using browser to get auth state (WAF bypass)")
                    auth_state_result = await self.get_auth_state_with_browser(force_ui_click=force_browser_ui_click)
                else:
                    auth_state_result = await self.get_auth_state(
                        client=client,
                        headers=headers,
                        force_browser_ui_click=force_browser_ui_click,
                    )

                if auth_state_result and auth_state_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got auth state for Linux.do: {auth_state_result['state']}")
                else:
                    error_msg = auth_state_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    result_data = {
                        "error_type": "linuxdo_auth_state_failed",
                        "error_summary": summarize_linuxdo_auth_state_error(error_msg),
                        "error_detail": error_msg,
                        "error": f"Failed to get Linux.do auth state: {error_msg}",
                    }
                    if oauth_attempt < max_oauth_attempts and should_retry_linuxdo_auth_state_failure(error_msg):
                        continue
                    return False, result_data

                success, result_data = await linuxdo.signin(
                    client_id=client_id_result["client_id"],
                    auth_state=auth_state_result["state"],
                    auth_cookies=auth_state_result.get("cookies", []),
                    cache_file_path=cache_file_path,
                )

                if success:
                    break

                if oauth_attempt < max_oauth_attempts and self._should_retry_linuxdo_oauth_once(result_data):
                    # 首轮如果是浏览器直接 fetch 到 state，但后续 authorize 仍失败，
                    # 下一轮强制切到页面 LinuxDO 按钮链路，兼容依赖前端点击初始化 provider 会话的站点。
                    if auth_state_result and auth_state_result.get("auth_state_via_browser") and not force_browser_ui_click:
                        force_browser_ui_click = True
                        print(
                            f"⚠️ {self.account_name}: Browser auth state did not finish Linux.do authorize successfully, "
                            "next retry will force LinuxDO continue button flow"
                        )
                    print(
                        f"⚠️ {self.account_name}: Linux.do authorize step failed with "
                        f"{result_data.get('error_type', 'unknown_error')}, will reset cookies/session and retry once"
                    )
                    continue

                break

            if not success and isinstance(result_data, dict):
                error_type = result_data.get("error_type", "")
                if error_type in {
                    "linuxdo_high_load",
                    "linuxdo_sso_provider_stuck",
                    "linuxdo_redirect_login",
                    "linuxdo_prewarmed_state_missing",
                    "linuxdo_prewarmed_state_invalid",
                }:
                    LinuxDoSessionManager.trip_circuit(
                        username,
                        result_data.get("error_detail") or result_data.get("error_summary") or error_type,
                    )

            bootstrap_cookies = {**waf_cookies}
            for cookie_dict in (auth_state_result or {}).get("cookies", []):
                cookie_name = cookie_dict.get("name")
                cookie_value = cookie_dict.get("value")
                if cookie_name and cookie_value is not None:
                    bootstrap_cookies[cookie_name] = cookie_value

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]
                merged_cookies = {**bootstrap_cookies, **user_cookies}

                # 保存 provider session 缓存
                _save_provider_session_cache(provider_cache_path, merged_cookies, api_user)
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
                frontend_callback_url = get_linuxdo_frontend_callback_url(self.provider_config, result_data)
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
                                merged_cookies = {**bootstrap_cookies, **user_cookies}

                                # 保存 provider session 缓存
                                _save_provider_session_cache(provider_cache_path, merged_cookies, api_user)
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
                            http_frontend_result = await self.complete_linuxdo_callback_with_http_frontend(
                                frontend_callback_url,
                                str(callback_url),
                                headers,
                                auth_cookies_list,
                            )
                            if http_frontend_result.get("success"):
                                merged_cookies = {**bootstrap_cookies, **http_frontend_result["cookies"]}
                                api_user = http_frontend_result["api_user"]
                                _save_provider_session_cache(provider_cache_path, merged_cookies, api_user)
                                print(f"✅ {self.account_name}: Frontend-first HTTP callback succeeded")
                                if login_only:
                                    return True, {"cookies": merged_cookies, "api_user": api_user}
                                return await self.check_in_with_cookies(merged_cookies, api_user)
                            frontend_http_error = http_frontend_result.get("error", "")
                            should_browser_fallback = (
                                should_try_browser_callback_fallback(error_msg, frontend_http_error)
                                or should_force_browser_callback_fallback_for_provider(self.provider_config.origin)
                            )
                            if not should_browser_fallback:
                                if 'state parameter is empty or mismatched' in (
                                    f'{error_msg} {frontend_http_error}'.lower()
                                ):
                                    print(f"ℹ️ {self.account_name}: Promoting runtime mode to same-context callback due to state mismatch")
                                    self._mark_active_callback_browser_complete('callback_state_mismatch')
                                return False, {"error": f"OAuth callback failed: {error_msg}"}
                            fallback_result = await self.complete_linuxdo_callback_with_browser(
                                frontend_callback_url,
                                auth_state_result.get("cookies", []),
                            )
                            if fallback_result.get("success"):
                                merged_cookies = {**bootstrap_cookies, **fallback_result["cookies"]}
                                api_user = fallback_result["api_user"]
                                _save_provider_session_cache(provider_cache_path, merged_cookies, api_user)
                                print(f"✅ {self.account_name}: Browser callback fallback succeeded")
                                self._mark_active_callback_browser_complete('browser_callback_fallback_succeeded')
                                if login_only:
                                    return True, {"cookies": merged_cookies, "api_user": api_user}
                                return await self.check_in_with_cookies(merged_cookies, api_user)
                            print(f"ℹ️ {self.account_name}: Promoting runtime mode to same-context callback after browser fallback failure")
                            self._mark_active_callback_browser_complete('browser_callback_fallback_failed')
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        http_frontend_result = await self.complete_linuxdo_callback_with_http_frontend(
                            frontend_callback_url,
                            str(callback_url),
                            headers,
                            auth_cookies_list,
                        )
                        if http_frontend_result.get("success"):
                            merged_cookies = {**bootstrap_cookies, **http_frontend_result["cookies"]}
                            api_user = http_frontend_result["api_user"]
                            _save_provider_session_cache(provider_cache_path, merged_cookies, api_user)
                            print(f"✅ {self.account_name}: Frontend-first HTTP callback succeeded")
                            if login_only:
                                return True, {"cookies": merged_cookies, "api_user": api_user}
                            return await self.check_in_with_cookies(merged_cookies, api_user)
                        frontend_http_error = http_frontend_result.get("error", "")
                        should_browser_fallback = (
                            should_try_browser_callback_fallback(
                                f"OAuth callback HTTP {response.status_code}",
                                frontend_http_error,
                            )
                            or should_force_browser_callback_fallback_for_provider(self.provider_config.origin)
                        )
                        if not should_browser_fallback:
                            return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                        fallback_result = await self.complete_linuxdo_callback_with_browser(
                            frontend_callback_url,
                            auth_state_result.get("cookies", []),
                        )
                        if fallback_result.get("success"):
                            merged_cookies = {**bootstrap_cookies, **fallback_result["cookies"]}
                            api_user = fallback_result["api_user"]
                            _save_provider_session_cache(provider_cache_path, merged_cookies, api_user)
                            print(f"✅ {self.account_name}: Browser callback fallback succeeded")
                            self._mark_active_callback_browser_complete('browser_callback_fallback_succeeded')
                            if login_only:
                                return True, {"cookies": merged_cookies, "api_user": api_user}
                            return await self.check_in_with_cookies(merged_cookies, api_user)
                        print(f"ℹ️ {self.account_name}: Promoting runtime mode to same-context callback after browser fallback failure")
                        self._mark_active_callback_browser_complete('browser_callback_fallback_failed')
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    http_frontend_result = await self.complete_linuxdo_callback_with_http_frontend(
                        frontend_callback_url,
                        str(callback_url),
                        headers,
                        auth_state_result.get("cookies", []),
                    )
                    if http_frontend_result.get("success"):
                        merged_cookies = {**bootstrap_cookies, **http_frontend_result["cookies"]}
                        api_user = http_frontend_result["api_user"]
                        _save_provider_session_cache(provider_cache_path, merged_cookies, api_user)
                        print(f"✅ {self.account_name}: Frontend-first HTTP callback succeeded")
                        if login_only:
                            return True, {"cookies": merged_cookies, "api_user": api_user}
                        return await self.check_in_with_cookies(merged_cookies, api_user)
                    frontend_http_error = http_frontend_result.get("error", "")
                    should_browser_fallback = (
                        should_try_browser_callback_fallback(str(callback_err), frontend_http_error)
                        or should_force_browser_callback_fallback_for_provider(self.provider_config.origin)
                    )
                    if not should_browser_fallback:
                        return False, {"error": f"OAuth callback error: {callback_err}"}
                    fallback_result = await self.complete_linuxdo_callback_with_browser(
                        frontend_callback_url,
                        auth_state_result.get("cookies", []),
                    )
                    if fallback_result.get("success"):
                        merged_cookies = {**bootstrap_cookies, **fallback_result["cookies"]}
                        api_user = fallback_result["api_user"]
                        _save_provider_session_cache(provider_cache_path, merged_cookies, api_user)
                        print(f"✅ {self.account_name}: Browser callback fallback succeeded")
                        self._mark_active_callback_browser_complete('browser_callback_fallback_succeeded')
                        if login_only:
                            return True, {"cookies": merged_cookies, "api_user": api_user}
                        return await self.check_in_with_cookies(merged_cookies, api_user)
                    print(f"ℹ️ {self.account_name}: Promoting runtime mode to same-context callback after browser fallback failure")
                    self._mark_active_callback_browser_complete('browser_callback_fallback_failed')
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

        # 解析账号配置
        cookies_data = self.account_config.cookies
        github_info = self.account_config.github
        linuxdo_info = self.account_config.linux_do

        waf_cookies = {}
        should_prefetch_waf_cookies = self.provider_config.needs_waf_cookies() and (bool(cookies_data) or bool(github_info))
        if should_prefetch_waf_cookies:
            waf_cookies = await self.get_waf_cookies_with_browser()
            if not waf_cookies:
                print(f"⚠️ {self.account_name}: Unable to get WAF cookies, continuing with empty cookies")
                waf_cookies = {}  # 确保 waf_cookies 是空字典而不是 None
            else:
                print(f"✅ {self.account_name}: WAF cookies obtained")
        elif self.provider_config.needs_waf_cookies():
            print(f"ℹ️ {self.account_name}: WAF bootstrap deferred for Linux.do flow, will reuse provider/cache first")
        else:
            print(f"ℹ️ {self.account_name}: Bypass WAF not required, using user cookies directly")

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
                # 特殊处理：有 get_cdk 的 provider（如 fuli_wheel, x666）
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

   
