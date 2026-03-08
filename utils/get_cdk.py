#!/usr/bin/env python3
"""
CDK 获取模块

提供各个 provider 的 CDK 获取函数
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import httpx

from utils.http_utils import proxy_resolve, response_resolve

if TYPE_CHECKING:
    from utils.config import AccountConfig

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


async def _get_fuli_session_cookies(account_config: "AccountConfig") -> dict | None:
    """通过浏览器登录 fuli.hxi.me 获取 session cookies

    Args:
        account_config: 账号配置对象，需要包含 linux_do 认证信息

    Returns:
        dict | None: cookies 字典，如果获取失败则返回 None
    """
    import hashlib
    import os

    from camoufox.async_api import AsyncCamoufox

    from utils.browser_utils import take_screenshot
    from utils.linuxdo_session import LinuxDoSessionManager

    account_name = account_config.get_display_name()
    linux_do = account_config.linux_do

    if not linux_do:
        return None

    username = linux_do.get("username")
    password = linux_do.get("password")

    if not username or not password:
        return None

    # 尝试获取共享的 Linux.do 会话
    shared_session = LinuxDoSessionManager.get_cached_session(username)

    # 确定 storage_state 来源
    storage_state_dir = "storage-states"
    os.makedirs(storage_state_dir, exist_ok=True)

    if shared_session:
        cache_file_path = shared_session.get_storage_state_path()
        print(f"ℹ️ {account_name}: Using shared Linux.do session for fuli.hxi.me")
    else:
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        cache_file_path = f"{storage_state_dir}/fuli_linuxdo_{username_hash}_storage_state.json"
        print(f"ℹ️ {account_name}: No shared session, using standalone cache for fuli.hxi.me")

    try:
        async with AsyncCamoufox(
            headless=True,
            humanize=True,
            locale="zh-CN",
        ) as browser:
            storage_state = cache_file_path if os.path.exists(cache_file_path) else None
            if storage_state:
                print(f"ℹ️ {account_name}: Found cache file, restoring storage state")

            context = await browser.new_context(storage_state=storage_state)
            page = await context.new_page()

            try:
                # 1. 先登录 linux.do
                print(f"ℹ️ {account_name}: Navigating to linux.do for fuli.hxi.me login")
                await page.goto("https://linux.do/login", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                await page.wait_for_timeout(1500)

                # 检查是否遇到 Cloudflare 人机验证
                page_title = await page.title()
                if "Just a moment" in page_title or "Verify" in page_title:
                    print(f"⚠️ {account_name}: Cloudflare verification detected, waiting...")
                    try:
                        await page.wait_for_function(
                            "!document.title.includes('Just a moment') && !document.title.includes('Verify')",
                            timeout=TIMEOUT_CLOUDFLARE
                        )
                        await page.wait_for_timeout(2000)
                        print(f"✅ {account_name}: Cloudflare verification completed")
                    except Exception as cf_err:
                        print(f"❌ {account_name}: Cloudflare verification timeout: {cf_err}")
                        return None

                current_url = page.url
                if "linux.do/login" in current_url:
                    print(f"ℹ️ {account_name}: Logging in to linux.do")
                    try:
                        await page.wait_for_selector("#login-account-name", timeout=TIMEOUT_ELEMENT_WAIT)
                    except Exception:
                        print(f"⚠️ {account_name}: Login form not found, page may be loading slowly")
                        await page.wait_for_timeout(2000)

                    await page.fill("#login-account-name", username, timeout=TIMEOUT_FILL)
                    await page.wait_for_timeout(500)
                    await page.fill("#login-account-password", password, timeout=TIMEOUT_FILL)
                    await page.wait_for_timeout(500)
                    await page.click("#login-button", timeout=TIMEOUT_CLICK)

                    try:
                        await page.wait_for_selector(".current-user", timeout=15000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    current_url = page.url
                    if "linux.do/login" in current_url:
                        print(f"❌ {account_name}: Failed to login to linux.do")
                        await take_screenshot(page, "fuli_linuxdo_login_failed", account_name)
                        return None

                    print(f"✅ {account_name}: Logged in to linux.do")
                    await context.storage_state(path=cache_file_path)
                else:
                    print(f"✅ {account_name}: Already logged in to linux.do (via cache)")

                # 2. 访问 fuli.hxi.me
                print(f"ℹ️ {account_name}: Navigating to fuli.hxi.me")
                await page.goto("https://fuli.hxi.me/", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                await page.wait_for_timeout(2000)

                # 3. 检查是否需要登录
                login_btn = await page.query_selector('button:has-text("登录"), a:has-text("登录")')
                if login_btn:
                    print(f"ℹ️ {account_name}: Clicking login button on fuli.hxi.me")
                    await login_btn.click()
                    try:
                        await page.wait_for_url("**connect.linux.do**", timeout=10000)
                    except Exception:
                        await page.wait_for_timeout(2000)

                    current_url = page.url
                    if "connect.linux.do" in current_url and "oauth2/authorize" in current_url:
                        print(f"ℹ️ {account_name}: At OAuth authorization page")
                        try:
                            await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=TIMEOUT_ELEMENT_WAIT)
                            allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                            if allow_btn:
                                print(f"ℹ️ {account_name}: Clicking authorize button")
                                await allow_btn.click()
                                await page.wait_for_timeout(2000)
                        except Exception as e:
                            print(f"⚠️ {account_name}: OAuth approve failed: {e}")

                    await context.storage_state(path=cache_file_path)
                    print(f"✅ {account_name}: Logged in to fuli.hxi.me")

                # 4. 获取 cookies
                cookies = await context.cookies()
                cookie_dict = {c["name"]: c["value"] for c in cookies if "fuli.hxi.me" in c.get("domain", "")}

                if "session" in cookie_dict:
                    print(f"✅ {account_name}: Got fuli.hxi.me session cookies")
                    return cookie_dict
                else:
                    print(f"❌ {account_name}: Session cookie not found in fuli.hxi.me")
                    await take_screenshot(page, "fuli_no_session", account_name)
                    return None

            except Exception as e:
                print(f"❌ {account_name}: Error getting fuli cookies: {e}")
                await take_screenshot(page, "fuli_error", account_name)
                return None
            finally:
                await page.close()
                await context.close()

    except Exception as e:
        print(f"❌ {account_name}: Error starting browser for fuli: {e}")
        return None


async def get_runawaytime_checkin_cdk(account_config: "AccountConfig") -> str | None:
    """获取 runawaytime 签到 CDK

    通过 fuli.hxi.me 签到获取 CDK
    支持两种方式：
    1. 使用配置中的 fuli_cookies
    2. 通过 linux.do 账号自动登录获取 cookies

    Args:
        account_config: 账号配置对象，需要包含 fuli_cookies 或 linux_do 认证信息

    Returns:
        str | None: CDK 字符串，如果获取失败则返回 None
    """
    account_name = account_config.get_display_name()
    fuli_cookies = account_config.get("fuli_cookies")
    proxy = account_config.proxy or account_config.get("global_proxy")

    # 如果没有 fuli_cookies，尝试通过浏览器登录获取
    if not fuli_cookies:
        linux_do = account_config.linux_do
        if linux_do and linux_do.get("username") and linux_do.get("password"):
            print(f"ℹ️ {account_name}: No fuli_cookies, trying browser login for fuli.hxi.me")
            try:
                fuli_cookies = await _get_fuli_session_cookies(account_config)
            except Exception as e:
                print(f"❌ {account_name}: Failed to get fuli cookies via browser: {e}")
                return None

        if not fuli_cookies:
            print(f"❌ {account_name}: fuli_cookies not found and browser login failed")
            return None

    http_proxy = proxy_resolve(proxy)
    
    try:
        client = httpx.Client(http2=False, timeout=30.0, proxy=http_proxy)
        try:
            # 构建基础请求头
            headers = {
                "accept": "*/*",
                "accept-language": "en,en-US;q=0.9,zh;q=0.8",
                "cache-control": "no-cache",
                "pragma": "no-cache",
                "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            }
            
            # 设置 cookies
            client.cookies.update(fuli_cookies)
            client.cookies.set("i18next", "en")
            
            # 先检查签到状态
            status_headers = headers.copy()
            status_headers.update({
                "referer": "https://fuli.hxi.me/",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            })
            
            status_response = client.get(
                "https://fuli.hxi.me/api/checkin/status",
                headers=status_headers,
                timeout=30
            )
            
            if status_response.status_code == 200:
                status_data = response_resolve(status_response, "get_checkin_status", account_name)
                if status_data and status_data.get("checked"):
                    print(f"✅ {account_name}: Already checked in today")
                    return None  # 已签到，无需再次签到
            
            # 执行签到
            checkin_headers = headers.copy()
            checkin_headers.update({
                "content-length": "0",
                "origin": "https://fuli.hxi.me",
                "referer": "https://fuli.hxi.me/",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            })
            
            response = client.post(
                "https://fuli.hxi.me/api/checkin",
                headers=checkin_headers,
                timeout=30
            )
            
            if response.status_code in [200, 400]:
                json_data = response_resolve(response, "execute_checkin", account_name)
                if json_data is None:
                    return None
                
                if json_data.get("success"):
                    code = json_data.get("code", "")
                    if code:
                        print(f"✅ {account_name}: Checkin successful! Code: {code}")
                        return code
                
                message = json_data.get("message", json_data.get("msg", ""))
                if "already" in message.lower() or "已经" in message or "已签" in message:
                    print(f"✅ {account_name}: Already checked in today")
                    return None
                
                print(f"❌ {account_name}: Checkin failed - {message}")
            
            return None
        finally:
            client.close()
    except Exception as e:
        print(f"❌ {account_name}: Error getting runawaytime checkin CDK - {e}")
        return None


async def get_runawaytime_wheel_cdk(account_config: "AccountConfig") -> list[str] | None:
    """获取 runawaytime 大转盘 CDK

    通过 fuli.hxi.me 大转盘获取 CDK，支持多次转盘
    支持两种方式：
    1. 使用配置中的 fuli_cookies
    2. 通过 linux.do 账号自动登录获取 cookies

    Args:
        account_config: 账号配置对象，需要包含 fuli_cookies 或 linux_do 认证信息

    Returns:
        list[str] | None: CDK 字符串列表，如果获取失败则返回 None
    """
    account_name = account_config.get_display_name()
    fuli_cookies = account_config.get("fuli_cookies")
    proxy = account_config.proxy or account_config.get("global_proxy")

    # 如果没有 fuli_cookies，尝试通过浏览器登录获取
    if not fuli_cookies:
        linux_do = account_config.linux_do
        if linux_do and linux_do.get("username") and linux_do.get("password"):
            print(f"ℹ️ {account_name}: No fuli_cookies, trying browser login for fuli.hxi.me")
            try:
                fuli_cookies = await _get_fuli_session_cookies(account_config)
            except Exception as e:
                print(f"❌ {account_name}: Failed to get fuli cookies via browser: {e}")
                return None

        if not fuli_cookies:
            print(f"❌ {account_name}: fuli_cookies not found and browser login failed")
            return None

    http_proxy = proxy_resolve(proxy)
    cdks: list[str] = []
    
    try:
        client = httpx.Client(http2=False, timeout=30.0, proxy=http_proxy)
        try:
            # 构建基础请求头
            headers = {
                "accept": "*/*",
                "accept-language": "en,en-US;q=0.9,zh;q=0.8",
                "cache-control": "no-cache",
                "pragma": "no-cache",
                "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            }
            
            # 设置 cookies
            client.cookies.update(fuli_cookies)
            client.cookies.set("i18next", "en")
            
            # 先检查大转盘状态
            status_headers = headers.copy()
            status_headers.update({
                "referer": "https://fuli.hxi.me/wheel",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            })
            
            status_response = client.get(
                "https://fuli.hxi.me/api/wheel/status",
                headers=status_headers,
                timeout=30
            )
            
            remaining = 0
            if status_response.status_code == 200:
                status_data = response_resolve(status_response, "get_wheel_status", account_name)
                if status_data:
                    remaining = status_data.get("remaining", 0)
                    if remaining <= 0:
                        print(f"ℹ️ {account_name}: No wheel spins remaining")
                        return None
                    print(f"ℹ️ {account_name}: {remaining} wheel spin(s) remaining")
            
            # 执行大转盘（循环直到 remaining <= 0）
            wheel_headers = headers.copy()
            wheel_headers.update({
                "content-length": "0",
                "origin": "https://fuli.hxi.me",
                "referer": "https://fuli.hxi.me/wheel",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            })
            
            spin_count = 0
            
            while remaining > 0:
                response = client.post(
                    "https://fuli.hxi.me/api/wheel",
                    headers=wheel_headers,
                    timeout=30
                )
                
                if response.status_code in [200, 400]:
                    json_data = response_resolve(response, "execute_wheel", account_name)
                    if json_data is None:
                        break
                    
                    if json_data.get("success"):
                        code = json_data.get("code", "")
                        # 从响应中更新 remaining
                        remaining = json_data.get("remaining", remaining - 1)
                        if code:
                            spin_count += 1
                            print(f"✅ {account_name}: Wheel spin #{spin_count} successful! Code: {code}, remaining: {remaining}")
                            cdks.append(code)
                            continue
                    
                    message = json_data.get("message", json_data.get("msg", ""))
                    if "already" in message.lower() or "已经" in message or "次数" in message or "no more" in message.lower():
                        print(f"ℹ️ {account_name}: No more wheel spins remaining")
                        break
                    
                    print(f"❌ {account_name}: Wheel spin #{spin_count + 1} failed - {message}")
                    break
                else:
                    break
            
            if cdks:
                print(f"✅ {account_name}: Total {len(cdks)} CDK(s) obtained from wheel")
                return cdks
            
            return None
        finally:
            client.close()
    except Exception as e:
        print(f"❌ {account_name}: Error getting runawaytime wheel CDK - {e}")
        return cdks if cdks else None


def get_b4u_cdk(account_config: "AccountConfig") -> list[str] | None:
    """获取 b4u 大转盘抽奖 CDK

    通过 tw.b4u.qzz.io/luckydraw 大转盘抽奖获取 CDK
    使用 Camoufox 浏览器自动化，通过 LinuxDo OAuth 登录福利站
    流程：登录 -> 点击开始抽奖 -> 获取 CDK

    Args:
        account_config: 账号配置对象，需要包含 linux_do 认证信息

    Returns:
        list[str] | None: CDK 字符串列表，如果获取失败则返回 None
    """
    import asyncio

    # 使用 asyncio 运行异步函数
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # 如果事件循环已在运行，创建新任务
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, _get_b4u_cdk_async(account_config))
                return future.result()
        else:
            return loop.run_until_complete(_get_b4u_cdk_async(account_config))
    except RuntimeError:
        # 没有事件循环，创建新的
        return asyncio.run(_get_b4u_cdk_async(account_config))


async def _get_b4u_cdk_async(account_config: "AccountConfig") -> list[str] | None:
    """异步获取 b4u 大转盘抽奖 CDK（带重试机制）

    使用 Camoufox 浏览器自动化完成整个流程
    登录流程（参考 x666 成功模式）：
    1. 先直接访问 linux.do/login 登录
    2. 登录成功后访问 b4u 触发 OAuth
    3. 执行抽奖获取 CDK
    """
    account_name = account_config.get_display_name()
    linux_do = account_config.linux_do

    if not linux_do:
        print(f"❌ {account_name}: linux.do credentials not found in account config for b4u")
        return None

    username = linux_do.get("username")
    password = linux_do.get("password")

    if not username or not password:
        print(f"❌ {account_name}: linux.do username or password not found")
        return None

    # 带重试机制的浏览器登录
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if attempt > 1:
                print(f"ℹ️ {account_name}: Retry attempt {attempt}/{MAX_RETRIES} for b4u")
                await asyncio.sleep(RETRY_DELAY)

            result = await _b4u_browser_impl(account_config, username, password)
            if result:
                return result
            else:
                last_error = "Browser operation returned no result"
                print(f"⚠️ {account_name}: Attempt {attempt} failed: {last_error}")

        except Exception as e:
            last_error = str(e)
            print(f"⚠️ {account_name}: Attempt {attempt} exception: {e}")

    print(f"❌ {account_name}: All {MAX_RETRIES} attempts failed for b4u. Last error: {last_error}")
    return None


async def _b4u_browser_impl(account_config: "AccountConfig", username: str, password: str) -> list[str] | None:
    """b4u 浏览器操作实现"""
    import hashlib
    import os

    from camoufox.async_api import AsyncCamoufox

    from utils.browser_utils import take_screenshot
    from utils.linuxdo_session import LinuxDoSessionManager

    account_name = account_config.get_display_name()

    # 尝试获取共享的 Linux.do 会话
    shared_session = LinuxDoSessionManager.get_cached_session(username)

    # 确定 storage_state 来源：优先使用共享会话
    storage_state_dir = "storage-states"
    os.makedirs(storage_state_dir, exist_ok=True)

    if shared_session:
        cache_file_path = shared_session.get_storage_state_path()
        print(f"ℹ️ {account_name}: Using shared Linux.do session for b4u")
    else:
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        cache_file_path = f"{storage_state_dir}/b4u_linuxdo_{username_hash}_storage_state.json"
        print(f"ℹ️ {account_name}: No shared session, using standalone cache for b4u")

    print(f"ℹ️ {account_name}: Starting Camoufox browser to get b4u CDK")

    try:
        async with AsyncCamoufox(
            headless=True,
            humanize=True,
            locale="zh-CN",
        ) as browser:
            # 只有在缓存文件存在时才加载 storage_state
            storage_state = cache_file_path if os.path.exists(cache_file_path) else None
            if storage_state:
                print(f"ℹ️ {account_name}: Found cache file, restoring storage state")
            else:
                print(f"ℹ️ {account_name}: No cache file found, starting fresh")

            context = await browser.new_context(storage_state=storage_state)
            page = await context.new_page()

            try:
                is_logged_in = False

                # 1. 先尝试直接访问 b4u 抽奖页面检查是否已登录
                print(f"ℹ️ {account_name}: Checking login status on b4u")
                await page.goto("https://tw.b4u.qzz.io/luckydraw", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                await page.wait_for_timeout(2000)

                current_url = page.url
                if "/login" not in current_url:
                    # 检查页面是否有抽奖按钮
                    try:
                        spin_btn = await page.query_selector('button:has-text("开始抽奖")')
                        if spin_btn:
                            is_logged_in = True
                            print(f"✅ {account_name}: Already logged in to b4u via cache")
                    except Exception:
                        # 页面可能正在导航，忽略错误
                        pass

                # 2. 如果未登录，先登录 linux.do
                if not is_logged_in:
                    print(f"ℹ️ {account_name}: Not logged in, starting linux.do login first")
                    await page.goto("https://linux.do/login", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                    await page.wait_for_timeout(1500)

                    current_url = page.url
                    if "linux.do/login" in current_url:
                        print(f"ℹ️ {account_name}: Filling linux.do credentials")
                        try:
                            # 等待登录表单加载
                            await page.wait_for_selector("#login-account-name", timeout=TIMEOUT_ELEMENT_WAIT)

                            await page.fill("#login-account-name", username, timeout=TIMEOUT_FILL)
                            await page.wait_for_timeout(500)
                            await page.fill("#login-account-password", password, timeout=TIMEOUT_FILL)
                            await page.wait_for_timeout(500)
                            await page.click("#login-button", timeout=TIMEOUT_CLICK)
                            # 等待登录完成：检测用户元素出现
                            try:
                                await page.wait_for_selector(".current-user", timeout=15000)
                            except Exception:
                                await page.wait_for_timeout(3000)
                        except Exception as e:
                            print(f"❌ {account_name}: Failed to fill login form: {e}")
                            await take_screenshot(page, "b4u_linuxdo_login_failed", account_name)
                            return None

                        current_url = page.url
                        if "linux.do/login" in current_url:
                            print(f"❌ {account_name}: Failed to login to linux.do")
                            await take_screenshot(page, "b4u_linuxdo_login_failed", account_name)
                            return None

                        print(f"✅ {account_name}: Logged in to linux.do")
                    else:
                        print(f"✅ {account_name}: Already logged in to linux.do (via cache)")

                    # 保存 linux.do 登录状态
                    await context.storage_state(path=cache_file_path)

                    # 3. 访问 b4u 登录页面触发 OAuth
                    print(f"ℹ️ {account_name}: Navigating to b4u login page")
                    await page.goto("https://tw.b4u.qzz.io/login", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                    await page.wait_for_timeout(1500)

                    # 点击 LinuxDo 登录按钮
                    login_btn = await page.query_selector('button:has-text("使用 Linux.do 登录")')
                    if login_btn:
                        print(f"ℹ️ {account_name}: Clicking LinuxDo login button")
                        await login_btn.click()
                        # 等待 OAuth 页面加载或直接跳转
                        try:
                            await page.wait_for_url("**connect.linux.do**", timeout=10000)
                        except Exception:
                            await page.wait_for_timeout(3000)

                        # 检查是否需要 OAuth 授权
                        current_url = page.url
                        print(f"ℹ️ {account_name}: URL after login click: {current_url}")

                        if "connect.linux.do" in current_url and "oauth2/authorize" in current_url:
                            print(f"ℹ️ {account_name}: At OAuth authorization page")
                            try:
                                await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=TIMEOUT_ELEMENT_WAIT)
                                allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                                if allow_btn:
                                    print(f"ℹ️ {account_name}: Clicking authorize button")
                                    await allow_btn.click()
                                    await page.wait_for_timeout(2000)
                            except Exception as e:
                                print(f"⚠️ {account_name}: OAuth approve failed: {e}")

                    # 保存登录状态
                    await context.storage_state(path=cache_file_path)
                    print(f"✅ {account_name}: Storage state saved")

                    # 确保回到抽奖页面
                    current_url = page.url
                    if "luckydraw" not in current_url:
                        print(f"ℹ️ {account_name}: Navigating to luckydraw page")
                        await page.goto("https://tw.b4u.qzz.io/luckydraw", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                        await page.wait_for_timeout(1500)

                # 4. 执行抽奖流程
                print(f"ℹ️ {account_name}: Starting lottery process")

                # 截图当前页面状态
                await take_screenshot(page, "b4u_luckydraw_page", account_name)

                # 检查今日剩余次数 - 尝试多种匹配方式
                remaining = 0
                try:
                    remaining_info = await page.evaluate("""() => {
                        const text = document.body.innerText;
                        // 尝试多种匹配模式
                        const patterns = [
                            /今日剩余次数[：:]\s*(\d+)/,
                            /剩余次数[：:]\s*(\d+)/,
                            /剩余\s*(\d+)\s*次/,
                            /还有\s*(\d+)\s*次/,
                            /(\d+)\s*次机会/,
                        ];
                        for (const p of patterns) {
                            const match = text.match(p);
                            if (match) {
                                return { found: true, value: match[1], pattern: p.toString() };
                            }
                        }
                        return { found: false, value: '0', pageText: text.substring(0, 500) };
                    }""")

                    if remaining_info.get('found'):
                        remaining = int(remaining_info.get('value', '0'))
                        print(f"ℹ️ {account_name}: Today's remaining spins: {remaining} (matched: {remaining_info.get('pattern')})")
                    else:
                        # 如果没匹配到，检查是否有抽奖按钮来判断
                        spin_btn = await page.query_selector('button:has-text("开始抽奖")')
                        if spin_btn:
                            is_disabled = await spin_btn.get_attribute("disabled")
                            if not is_disabled:
                                remaining = 5  # 假设有5次机会
                                print(f"ℹ️ {account_name}: Could not find remaining count, but spin button is active, assuming {remaining} spins")
                            else:
                                print(f"ℹ️ {account_name}: Spin button is disabled, no spins remaining")
                        else:
                            print(f"⚠️ {account_name}: Could not find remaining spins info, page text: {remaining_info.get('pageText', '')[:200]}")
                except Exception as e:
                    print(f"⚠️ {account_name}: Could not get remaining spins: {e}")
                    # 检查是否有可用的抽奖按钮
                    spin_btn = await page.query_selector('button:has-text("开始抽奖")')
                    if spin_btn:
                        remaining = 5  # 假设有5次
                        print(f"ℹ️ {account_name}: Error getting count but spin button exists, assuming {remaining} spins")

                if remaining <= 0:
                    print(f"ℹ️ {account_name}: No spins remaining today, checking my-codes page...")
                    # 不直接返回，继续检查 my-codes 页面

                # 循环抽奖直到次数用完（只负责抽奖，CDK 从 my-codes 页面统一获取）
                spin_count = 0
                prize_count = 0
                max_retries = 3  # 最大重试次数

                while remaining > 0:
                    # 查找开始抽奖按钮（每次都重新查找，因为页面可能刷新）
                    spin_btn = None
                    for retry in range(max_retries):
                        spin_btn = await page.query_selector('button:has-text("开始抽奖")')
                        if spin_btn:
                            break
                        # 如果没找到，可能是弹窗覆盖，尝试关闭弹窗
                        close_btn = await page.query_selector('button:has-text("确定"), button:has-text("关闭"), button:has-text("OK"), button:has-text("知道了")')
                        if close_btn:
                            print(f"ℹ️ {account_name}: Closing dialog before retry...")
                            await close_btn.click()
                            await page.wait_for_timeout(1000)
                        else:
                            # 可能需要刷新页面
                            if retry == max_retries - 1:
                                print(f"ℹ️ {account_name}: Refreshing luckydraw page...")
                                await page.goto("https://tw.b4u.qzz.io/luckydraw", wait_until="domcontentloaded")
                                await page.wait_for_timeout(3000)
                            else:
                                await page.wait_for_timeout(2000)

                    if not spin_btn:
                        print(f"⚠️ {account_name}: Spin button not found after {max_retries} retries")
                        await take_screenshot(page, "b4u_spin_btn_not_found", account_name)
                        break

                    # 检查按钮是否可点击
                    is_disabled = await spin_btn.get_attribute("disabled")
                    if is_disabled:
                        print(f"ℹ️ {account_name}: Spin button is disabled")
                        break

                    # 在点击抽奖前，先发送 Next.js Server Action 请求刷新页面状态
                    spin_count += 1
                    print(f"ℹ️ {account_name}: Sending server action before spin #{spin_count}")
                    try:
                        server_action_result = await page.evaluate("""async () => {
                            try {
                                const response = await fetch('/luckydraw', {
                                    method: 'POST',
                                    credentials: 'include',
                                    headers: {
                                        'accept': 'text/x-component',
                                        'content-type': 'text/plain;charset=UTF-8',
                                        'next-action': 'f9d4d674b6dc56eed69256e6f809e1a6f65babf5',
                                        'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22(dashboard)%22%2C%7B%22children%22%3A%5B%22luckydraw%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fluckydraw%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
                                    },
                                    body: '[]'
                                });
                                return { ok: response.ok, status: response.status };
                            } catch (e) {
                                return { ok: false, error: e.message };
                            }
                        }""")
                        if server_action_result and server_action_result.get('ok'):
                            print(f"✅ {account_name}: Server action completed (status: {server_action_result.get('status')})")
                        else:
                            print(f"⚠️ {account_name}: Server action response: {server_action_result}")
                        await page.wait_for_timeout(500)  # 等待服务端处理
                    except Exception as e:
                        print(f"⚠️ {account_name}: Server action request failed: {e}")

                    # 点击抽奖
                    print(f"ℹ️ {account_name}: Clicking spin button (spin #{spin_count})")
                    await spin_btn.click()
                    await page.wait_for_timeout(6000)  # 等待转盘动画完成

                    # 检查抽奖结果（只判断是否中奖，不获取 CDK）
                    result = await page.evaluate("""() => {
                        const text = document.body.innerText;
                        // 检查是否有 CDK 格式的文本（中奖）
                        const cdkMatch = text.match(/([a-f0-9]{32})/i);
                        if (cdkMatch) {
                            return { won: true, cdk: cdkMatch[1] };
                        }
                        // 检查是否显示未中奖信息
                        if (text.includes('谢谢参与') || text.includes('未中奖') || text.includes('再接再厉')) {
                            return { won: false, reason: 'no_prize' };
                        }
                        return { won: false, reason: 'unknown' };
                    }""")

                    if result.get('won'):
                        prize_count += 1
                        print(f"✅ {account_name}: Spin #{spin_count} won! CDK: {result.get('cdk', 'unknown')}")
                    else:
                        reason = result.get('reason', 'unknown')
                        if reason == 'no_prize':
                            print(f"ℹ️ {account_name}: Spin #{spin_count} - No prize this time")
                        else:
                            print(f"⚠️ {account_name}: Spin #{spin_count} - Unknown result")
                            await take_screenshot(page, f"b4u_spin_{spin_count}_unknown", account_name)

                    # 关闭结果弹窗（包括 sonner toast 通知）
                    try:
                        # 先尝试用 JavaScript 关闭所有 toast 通知
                        await page.evaluate("""() => {
                            // 移除所有 sonner toast
                            document.querySelectorAll('[data-sonner-toast]').forEach(el => el.remove());
                            // 移除 toast 容器
                            document.querySelectorAll('section[aria-label="Notifications"]').forEach(el => el.remove());
                        }""")
                        await page.wait_for_timeout(500)

                        # 再尝试点击关闭按钮
                        close_btn = await page.query_selector('button:has-text("确定"), button:has-text("关闭"), button:has-text("OK"), button:has-text("知道了")')
                        if close_btn:
                            await close_btn.click()
                            await page.wait_for_timeout(500)
                    except Exception:
                        pass

                    remaining -= 1
                    # 短暂等待后继续下一次
                    await page.wait_for_timeout(1500)

                print(f"ℹ️ {account_name}: Lottery completed - {spin_count} spins, {prize_count} prizes")

                # 访问"我的兑换码"页面获取今日所有 CDK（统一从这里获取，而不是从转盘结果）
                print(f"ℹ️ {account_name}: Checking my-codes page for today's CDKs")
                await page.goto("https://tw.b4u.qzz.io/my-codes", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                await page.wait_for_timeout(2000)

                # 截图以便调试
                await take_screenshot(page, "b4u_my_codes_page", account_name)

                # 先获取页面结构信息用于调试
                page_info = await page.evaluate("""() => {
                    // 获取表格的列标题
                    const headers = Array.from(document.querySelectorAll('th')).map(th => th.innerText.trim());

                    // 获取所有表格行
                    const rows = Array.from(document.querySelectorAll('tbody tr')).slice(0, 5).map(tr => {
                        const cells = Array.from(tr.querySelectorAll('td'));
                        return cells.map(td => td.innerText.trim().substring(0, 50));
                    });

                    return { headers, sampleRows: rows };
                }""")
                print(f"ℹ️ {account_name}: Page structure - Headers: {page_info.get('headers', [])}")
                print(f"ℹ️ {account_name}: Sample rows: {page_info.get('sampleRows', [])}")

                # 从页面提取今天的 CDK 和面额信息
                # 根据页面结构：表格列为 ['兑换码', '面额', '来源', '获取时间', '操作']
                # 使用北京时间 (UTC+8) 判断"今天"
                today_cdks = await page.evaluate("""() => {
                    const cdks = [];
                    let totalQuota = 0;
                    const rows = document.querySelectorAll('tbody tr');

                    // 获取北京时间的今天日期字符串 (格式: YYYY-MM-DD)
                    const now = new Date();
                    const beijingTime = new Date(now.getTime() + (8 * 60 * 60 * 1000) + (now.getTimezoneOffset() * 60 * 1000));
                    const todayStr = beijingTime.getFullYear() + '-' +
                                     String(beijingTime.getMonth() + 1).padStart(2, '0') + '-' +
                                     String(beijingTime.getDate()).padStart(2, '0');

                    console.log('Beijing time today:', todayStr);

                    for (const row of rows) {
                        const cells = row.querySelectorAll('td');
                        if (cells.length >= 4) {
                            const cdk = cells[0].innerText.trim();
                            const quota = parseInt(cells[1].innerText.trim()) || 0;  // 面额列
                            const time = cells[3].innerText.trim();  // 获取时间列

                            // 检查是否是有效的 CDK 格式且是今天的
                            if (cdk && /^[a-f0-9]{32}$/i.test(cdk) && time.startsWith(todayStr)) {
                                cdks.push(cdk);
                                totalQuota += quota;
                            }
                        }
                    }

                    return { cdks, todayStr, totalQuota };
                }""")

                beijing_today = today_cdks.get('todayStr', 'unknown')
                today_cdk_list = today_cdks.get('cdks', [])
                total_quota = today_cdks.get('totalQuota', 0)
                print(f"ℹ️ {account_name}: Beijing time today: {beijing_today}")
                print(f"ℹ️ {account_name}: Found {len(today_cdk_list)} CDK(s) from today, total quota: {total_quota}")

                if today_cdk_list:
                    print(f"✅ {account_name}: Total {len(today_cdk_list)} CDK(s) to redeem, total quota: {total_quota}")
                    return {"type": "cdk_list", "cdks": today_cdk_list, "total_quota": total_quota, "spin_count": len(today_cdk_list)}
                else:
                    print(f"ℹ️ {account_name}: No CDKs from today found on my-codes page")
                    return {"type": "cdk_list", "cdks": [], "total_quota": 0, "spin_count": spin_count}

            except Exception as e:
                print(f"❌ {account_name}: Error in b4u CDK process: {e}")
                await take_screenshot(page, "b4u_error", account_name)
                return None
            finally:
                await page.close()
                await context.close()

    except Exception as e:
        print(f"❌ {account_name}: Error starting Camoufox for b4u: {e}")
        return None


def get_x666_cdk(account_config: "AccountConfig") -> str | None:
    """执行 x666 签到大转盘

    通过 qd.x666.me 执行签到大转盘，不返回 CDK（签到奖励直接到账）

    流程：
    1. 尝试使用配置中的 access_token
    2. 如果 token 无效或不存在，通过浏览器 LinuxDo OAuth 登录获取新 token
    3. 调用签到 API 执行大转盘

    Args:
        account_config: 账号配置对象，需要包含 linux_do 认证信息

    Returns:
        str | None: 签到成功返回 "checkin_success"，失败返回 None
    """
    import asyncio

    # 使用 asyncio 运行异步函数
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # 如果事件循环已在运行，创建新任务
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, _get_x666_checkin_async(account_config))
                return future.result()
        else:
            return loop.run_until_complete(_get_x666_checkin_async(account_config))
    except RuntimeError:
        # 没有事件循环，创建新的
        return asyncio.run(_get_x666_checkin_async(account_config))


async def _get_x666_checkin_async(account_config: "AccountConfig") -> str | None:
    """异步执行 x666 签到大转盘（带重试机制）

    注意：qd.x666.me 和 up.x666.me 共享同一个 OAuth 应用，
    OAuth 回调地址是 up.x666.me，所以需要在 up.x666.me 获取 token，
    然后用这个 token 调用 qd.x666.me 的签到 API。

    登录流程参考 sign_in_with_linuxdo.py：
    1. 先直接访问 linux.do/login 登录
    2. 登录成功后访问 up.x666.me 触发 OAuth
    3. 从 localStorage 获取 token
    """
    account_name = account_config.get_display_name()
    linux_do = account_config.linux_do
    access_token = account_config.get("access_token")

    # 如果有 access_token，先尝试使用它
    if access_token:
        print(f"ℹ️ {account_name}: Trying existing access_token for x666 checkin")
        result = await _execute_x666_checkin_with_token(account_name, access_token, None)
        if result:
            return result
        print(f"ℹ️ {account_name}: Existing token invalid or expired, will login via browser")

    # 检查是否有 linux_do 配置（仅在 token 不可用时才需要）
    if not linux_do:
        print(f"❌ {account_name}: linux.do credentials not found for x666 checkin fallback")
        return None

    username = linux_do.get("username")
    password = linux_do.get("password")

    if not username or not password:
        print(f"❌ {account_name}: linux.do username or password not found")
        return None

    # 通过浏览器登录获取新 token（带重试机制）
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if attempt > 1:
                print(f"ℹ️ {account_name}: Retry attempt {attempt}/{MAX_RETRIES} for x666 browser login")
                await asyncio.sleep(RETRY_DELAY)

            result = await _x666_browser_login_impl(account_config, username, password)
            if result:
                return result
            else:
                last_error = "Browser login returned no result"
                print(f"⚠️ {account_name}: Attempt {attempt} failed: {last_error}")

        except Exception as e:
            last_error = str(e)
            print(f"⚠️ {account_name}: Attempt {attempt} exception: {e}")

    print(f"❌ {account_name}: All {MAX_RETRIES} attempts failed for x666. Last error: {last_error}")
    return None


async def _x666_browser_login_impl(account_config: "AccountConfig", username: str, password: str) -> dict | None:
    """x666 浏览器登录实现"""
    import hashlib
    import json
    import os

    from camoufox.async_api import AsyncCamoufox

    from utils.browser_utils import (
        attempt_linuxdo_human_verification,
        detect_linuxdo_page_guard,
        has_linuxdo_human_verification,
        save_page_content_to_file,
        take_screenshot,
        wait_for_linuxdo_login_ready,
    )
    from utils.linuxdo_session import LinuxDoSessionManager

    account_name = account_config.get_display_name()
    print(f"ℹ️ {account_name}: Starting browser login for x666 checkin")

    storage_state_dir = "storage-states"
    os.makedirs(storage_state_dir, exist_ok=True)
    username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
    x666_cache_file_path = f"{storage_state_dir}/x666_linuxdo_{username_hash}_storage_state.json"

    # 强制复用当前更稳的 LinuxDoSession 逻辑
    shared_session = await LinuxDoSessionManager.get_session(username, password, auto_login=True)
    cache_file_path = shared_session.get_storage_state_path()
    print(f"ℹ️ {account_name}: Using shared Linux.do session for x666")

    try:
        async with AsyncCamoufox(
            headless=True,
            humanize=True,
            locale="en-US",
        ) as browser:
            def load_storage_state(path: str) -> dict | None:
                if not path or not os.path.exists(path):
                    return None
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except Exception as load_err:
                    print(f"⚠️ {account_name}: Failed to load storage state {path}: {load_err}")
                    return None

            def merge_storage_states(shared_path: str, x666_path: str) -> dict | str | None:
                shared_state = load_storage_state(shared_path)
                x666_state = load_storage_state(x666_path)

                if shared_state and x666_state:
                    merged_state = {
                        'cookies': [],
                        'origins': [],
                    }

                    cookie_map = {}
                    for state in [x666_state, shared_state]:
                        for cookie in state.get('cookies', []):
                            cookie_key = (
                                cookie.get('name', ''),
                                cookie.get('domain', ''),
                                cookie.get('path', '/'),
                            )
                            cookie_map[cookie_key] = cookie
                    merged_state['cookies'] = list(cookie_map.values())

                    origin_map = {}
                    for state in [shared_state, x666_state]:
                        for origin_item in state.get('origins', []):
                            origin = origin_item.get('origin')
                            if not origin:
                                continue

                            local_storage_map = {
                                item.get('name'): item
                                for item in origin_map.get(origin, {}).get('localStorage', [])
                                if item.get('name')
                            }
                            for item in origin_item.get('localStorage', []):
                                item_name = item.get('name')
                                if not item_name:
                                    continue
                                if item_name not in local_storage_map or state is shared_state:
                                    local_storage_map[item_name] = item

                            origin_map[origin] = {
                                'origin': origin,
                                'localStorage': list(local_storage_map.values()),
                            }

                    merged_state['origins'] = list(origin_map.values())
                    print(f"ℹ️ {account_name}: Merged shared Linux.do state with x666 cache state")
                    return merged_state

                if shared_state:
                    return shared_state
                if x666_state:
                    return x666_state
                if shared_path and os.path.exists(shared_path):
                    return shared_path
                if x666_path and os.path.exists(x666_path):
                    return x666_path
                return None

            # 共享 Linux.do 会话必须优先级更高，避免旧 x666 缓存覆盖新会话
            storage_state = merge_storage_states(cache_file_path, x666_cache_file_path)
            if storage_state:
                print(f"ℹ️ {account_name}: Found cache file, restoring storage state")
            else:
                print(f"ℹ️ {account_name}: No cache file found, starting fresh")

            context = await browser.new_context(storage_state=storage_state)
            page = await context.new_page()

            try:
                async def get_valid_token_from_page() -> str | None:
                    token = await page.evaluate("() => localStorage.getItem('userToken')")
                    if not token:
                        return None

                    print(f"ℹ️ {account_name}: Found token in page localStorage, validating on current host")
                    if await _verify_token_in_browser(page, token):
                        return token

                    print(f"⚠️ {account_name}: Browser token validation failed, clearing stale localStorage token")
                    await page.evaluate(
                        """() => {
                            localStorage.removeItem('userToken');
                            sessionStorage.removeItem('userToken');
                        }"""
                    )
                    return None

                async def get_auth_url() -> str | None:
                    try:
                        auth_data = await page.evaluate("""async () => {
                            const response = await fetch('/api/auth/login', {
                                headers: { 'Accept': 'application/json' }
                            });
                            return await response.json();
                        }""")
                    except Exception as auth_err:
                        print(f"⚠️ {account_name}: Failed to fetch x666 auth_url in browser: {auth_err}")
                        return None

                    auth_url = auth_data.get('auth_url') if isinstance(auth_data, dict) else None
                    if auth_url:
                        print(f"ℹ️ {account_name}: Got auth_url for x666 OAuth")
                    else:
                        print(f"⚠️ {account_name}: x666 auth_url missing from response: {auth_data}")
                    return auth_url

                async def ensure_linuxdo_login() -> bool:
                    print(f"ℹ️ {account_name}: Navigating to linux.do/login for x666 fallback")
                    await page.goto('https://linux.do/login', wait_until='domcontentloaded', timeout=TIMEOUT_PAGE_LOAD)

                    current_url = page.url
                    if 'linux.do/login' not in current_url and 'linux.do' in current_url:
                        print(f"✅ {account_name}: Shared Linux.do session already logged in ({current_url})")
                        return True

                    try:
                        await wait_for_linuxdo_login_ready(page, account_name, timeout=TIMEOUT_ELEMENT_WAIT)
                    except Exception as ready_err:
                        guard = await detect_linuxdo_page_guard(page)
                        print(f"⚠️ {account_name}: Linux.do login form not ready: {ready_err}")
                        if guard.get('human_verification'):
                            solved = await attempt_linuxdo_human_verification(page, account_name)
                            if not solved:
                                await save_page_content_to_file(
                                    page,
                                    'x666_linuxdo_hcaptcha_before_login_ready',
                                    account_name,
                                    prefix='x666'
                                )
                                await take_screenshot(page, 'x666_linuxdo_hcaptcha_before_login_ready', account_name)
                                return False
                        elif guard.get('cloudflare_challenge'):
                            await page.wait_for_timeout(3000)
                        else:
                            await page.wait_for_timeout(2000)
                        await wait_for_linuxdo_login_ready(page, account_name, timeout=TIMEOUT_ELEMENT_WAIT)

                    await page.fill('#login-account-name', username, timeout=TIMEOUT_FILL)
                    await page.wait_for_timeout(500)
                    await page.fill('#login-account-password', password, timeout=TIMEOUT_FILL)
                    await page.wait_for_timeout(500)

                    if await has_linuxdo_human_verification(page):
                        solved = await attempt_linuxdo_human_verification(page, account_name)
                        if not solved:
                            await save_page_content_to_file(page, 'x666_linuxdo_hcaptcha_detected', account_name, prefix='x666')
                            await take_screenshot(page, 'x666_linuxdo_hcaptcha_detected', account_name)
                            return False

                    await page.click('#login-button', timeout=TIMEOUT_CLICK)
                    try:
                        await page.wait_for_selector('.current-user', timeout=15000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    post_login_guard = await detect_linuxdo_page_guard(page)
                    if 'linux.do/login' in page.url and post_login_guard.get('human_verification'):
                        solved = await attempt_linuxdo_human_verification(page, account_name)
                        if solved:
                            print(f"ℹ️ {account_name}: Human Verification solved after submit, retrying Linux.do login once")
                            await page.click('#login-button', timeout=TIMEOUT_CLICK)
                            await page.wait_for_timeout(5000)
                            post_login_guard = await detect_linuxdo_page_guard(page)

                        if 'linux.do/login' in page.url and post_login_guard.get('human_verification'):
                            await save_page_content_to_file(
                                page,
                                'x666_linuxdo_hcaptcha_after_login_click',
                                account_name,
                                prefix='x666'
                            )
                            await take_screenshot(page, 'x666_linuxdo_hcaptcha_after_login_click', account_name)
                            return False

                    current_url = page.url
                    if 'linux.do/login' in current_url:
                        print(f"❌ {account_name}: Linux.do login still not completed, current url: {current_url}")
                        await save_page_content_to_file(page, 'x666_linuxdo_login_failed', account_name, prefix='x666')
                        await take_screenshot(page, 'x666_linuxdo_login_failed', account_name)
                        return False

                    print(f"✅ {account_name}: Linux.do login ready for x666 OAuth")
                    return True

                print(f"ℹ️ {account_name}: Checking x666 token state on up.x666.me")
                await page.goto('https://up.x666.me', wait_until='domcontentloaded', timeout=TIMEOUT_PAGE_LOAD)
                await page.wait_for_timeout(1500)

                token = await get_valid_token_from_page()
                if token:
                    print(f"✅ {account_name}: Reusing valid token from x666 page cache")
                    await context.storage_state(path=x666_cache_file_path)
                    return await _execute_x666_checkin_with_token(account_name, token, None)

                print(f"ℹ️ {account_name}: Shared Linux.do session is ready, starting x666 OAuth")
                auth_url = await get_auth_url()
                if not auth_url:
                    await save_page_content_to_file(page, 'x666_auth_url_missing', account_name, prefix='x666')
                    await take_screenshot(page, 'x666_auth_url_missing', account_name)
                    return None

                for flow_round in range(1, 5):
                    if flow_round > 1:
                        print(f"ℹ️ {account_name}: Continuing x666 OAuth flow round {flow_round}")

                    await page.goto(auth_url, wait_until='domcontentloaded', timeout=TIMEOUT_PAGE_LOAD)
                    await page.wait_for_timeout(1500)
                    current_url = page.url
                    print(f"ℹ️ {account_name}: x666 OAuth current URL: {current_url}")

                    if 'linux.do/login' in current_url:
                        print(f"ℹ️ {account_name}: x666 OAuth redirected to Linux.do login")
                        login_ok = await ensure_linuxdo_login()
                        if not login_ok:
                            return None
                        continue

                    if 'linux.do/session/sso_provider' in current_url:
                        print(f"ℹ️ {account_name}: x666 OAuth reached linux.do/session/sso_provider, waiting for redirect")
                        try:
                            await page.wait_for_url('**connect.linux.do/**', timeout=15000)
                        except Exception:
                            await page.wait_for_timeout(3000)
                        current_url = page.url
                        print(f"ℹ️ {account_name}: URL after sso_provider wait: {current_url}")
                        if 'linux.do/session/sso_provider' in current_url:
                            await save_page_content_to_file(page, 'x666_sso_provider_stuck', account_name, prefix='x666')
                            await take_screenshot(page, 'x666_sso_provider_stuck', account_name)

                    if 'connect.linux.do' in current_url and 'oauth2/authorize' in current_url:
                        print(f"ℹ️ {account_name}: At x666 OAuth authorization page, waiting for approve button")
                        try:
                            await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=TIMEOUT_ELEMENT_WAIT)
                            allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                            if allow_btn:
                                print(f"ℹ️ {account_name}: Clicking x666 authorize button")
                                await allow_btn.click()
                                await page.wait_for_timeout(2000)
                        except Exception as approve_err:
                            print(f"⚠️ {account_name}: x666 OAuth approve failed: {approve_err}")
                            await save_page_content_to_file(page, 'x666_oauth_approve_failed', account_name, prefix='x666')
                            await take_screenshot(page, 'x666_oauth_approve_failed', account_name)

                    try:
                        await page.wait_for_url('**up.x666.me/**', timeout=TIMEOUT_NAVIGATION)
                    except Exception:
                        await page.wait_for_timeout(1500)

                    current_url = page.url
                    print(f"ℹ️ {account_name}: x666 OAuth final URL: {current_url}")

                    if 'token=' in current_url:
                        await page.wait_for_timeout(2000)

                    token = await get_valid_token_from_page()
                    if token:
                        print(f"✅ {account_name}: Successfully got valid token via x666 browser login")
                        await context.storage_state(path=x666_cache_file_path)
                        return await _execute_x666_checkin_with_token(account_name, token, None)

                print(f"❌ {account_name}: Failed to get valid token after x666 OAuth flow")
                await save_page_content_to_file(page, 'x666_login_failed', account_name, prefix='x666')
                await take_screenshot(page, 'x666_login_failed', account_name)
                return None

            except Exception as e:
                print(f"❌ {account_name}: Error in browser login: {e}")
                await save_page_content_to_file(page, "x666_error", account_name, prefix="x666")
                await take_screenshot(page, "x666_error", account_name)
                return None
            finally:
                await page.close()
                await context.close()

    except Exception as e:
        print(f"❌ {account_name}: Error starting browser: {e}")
        return None


async def _verify_token_in_browser(page, token: str) -> bool:
    """在浏览器中验证 token 是否有效"""
    try:
        result = await page.evaluate(f"""async () => {{
            const response = await fetch('/api/user/info', {{
                headers: {{ 'Authorization': 'Bearer {token}' }}
            }});
            const data = await response.json();
            return data.success === true;
        }}""")
        return result
    except Exception:
        return False


async def _execute_x666_checkin_with_token(account_name: str, token: str, http_proxy: str | None = None) -> dict | None:
    """使用 token 执行 x666 签到

    Returns:
        dict | None: 成功返回 {"type": "checkin_success", "quota": 获得额度, "balance": 新余额}
    """
    print(f"ℹ️ {account_name}: Executing x666 checkin with token")

    try:
        client = httpx.Client(http2=True, timeout=30.0)
        try:
            x666_origins = [
                'https://up.x666.me',
                'https://qd.x666.me',
            ]

            for origin in x666_origins:
                headers = {
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                    'Origin': origin,
                    'Referer': f'{origin}/',
                }
                status_url = f'{origin}/api/checkin/status'
                spin_url = f'{origin}/api/checkin/spin'

                print(f"ℹ️ {account_name}: Trying x666 checkin endpoint on {origin}")
                status_resp = client.get(status_url, headers=headers)

                if status_resp.status_code == 401:
                    print(f"⚠️ {account_name}: Token unauthorized on {origin}, trying next x666 origin")
                    continue

                if status_resp.status_code == 200:
                    status_data = response_resolve(status_resp, 'get_checkin_status', account_name)
                    if status_data and status_data.get('success'):
                        if not status_data.get('can_spin'):
                            today_record = status_data.get('today_record', {})
                            quota = today_record.get('quota_amount', 0) if today_record else 0
                            balance = status_data.get('balance', 0)
                            print(f"✅ {account_name}: Already checked in today on {origin}, quota: {quota}, balance: {balance}")
                            return {'type': 'checkin_success', 'quota': quota, 'balance': balance}
                    elif status_data:
                        error_msg = status_data.get('message', 'Unknown error')
                        if 'token' in error_msg.lower() or 'unauthorized' in error_msg.lower():
                            print(f"⚠️ {account_name}: Token invalid on {origin}: {error_msg}")
                            continue
                        print(f"❌ {account_name}: Failed to get checkin status on {origin}: {error_msg}")
                        continue
                else:
                    print(f"⚠️ {account_name}: Checkin status request failed on {origin} with status {status_resp.status_code}")
                    continue

                spin_resp = client.post(spin_url, headers=headers)

                if spin_resp.status_code == 401:
                    print(f"⚠️ {account_name}: Spin request unauthorized on {origin}, trying next x666 origin")
                    continue

                if spin_resp.status_code == 200:
                    spin_data = response_resolve(spin_resp, 'execute_checkin_spin', account_name)
                    if spin_data and spin_data.get('success'):
                        quota = spin_data.get('quota', 0)
                        label = spin_data.get('label', '')
                        new_balance = spin_data.get('new_balance', 0)
                        message = spin_data.get('message', f'获得 {label}')
                        print(f"✅ {account_name}: Checkin successful on {origin}! {message}, new balance: {new_balance}")
                        return {'type': 'checkin_success', 'quota': quota, 'balance': new_balance}
                    elif spin_data:
                        error_msg = spin_data.get('message', 'Unknown error')
                        if '已签到' in error_msg or 'already' in error_msg.lower():
                            print(f"✅ {account_name}: Already checked in today on {origin}")
                            return {'type': 'checkin_success', 'quota': 0, 'balance': 0}
                        if 'token' in error_msg.lower() or 'unauthorized' in error_msg.lower():
                            print(f"⚠️ {account_name}: Token invalid during spin on {origin}: {error_msg}")
                            continue
                        print(f"❌ {account_name}: Checkin failed on {origin}: {error_msg}")
                        continue

                print(f"⚠️ {account_name}: Checkin spin request failed on {origin} with status {spin_resp.status_code}")

            print(f"❌ {account_name}: All x666 checkin endpoints rejected the token")
            return None

        finally:
            client.close()

    except Exception as e:
        print(f"❌ {account_name}: Error executing checkin: {e}")
        return None


def get_fuli_wheel_cdk(account_config: "AccountConfig") -> str | None:
    """执行 fuli.hxi.me 大转盘抽奖

    通过 fuli.hxi.me/wheel 执行大转盘抽奖，奖励直接到账（不返回 CDK）
    每天有 2 次抽奖机会

    流程：
    1. 通过浏览器 LinuxDo OAuth 登录获取 session cookie
    2. 调用抽奖 API 执行大转盘（最多 2 次）

    Args:
        account_config: 账号配置对象，需要包含 linux_do 认证信息

    Returns:
        str | None: 抽奖成功返回 "wheel_success"，失败返回 None
    """
    import asyncio

    # 使用 asyncio 运行异步函数
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # 如果事件循环已在运行，创建新任务
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, _get_fuli_wheel_async(account_config))
                return future.result()
        else:
            return loop.run_until_complete(_get_fuli_wheel_async(account_config))
    except RuntimeError:
        # 没有事件循环，创建新的
        return asyncio.run(_get_fuli_wheel_async(account_config))


async def _get_fuli_wheel_async(account_config: "AccountConfig") -> str | None:
    """异步执行 fuli.hxi.me 大转盘抽奖（带重试机制）

    登录流程：
    1. 先直接访问 linux.do/login 登录
    2. 登录成功后访问 fuli.hxi.me/wheel 触发 OAuth
    3. 获取 session cookie 后调用抽奖 API
    """
    account_name = account_config.get_display_name()
    linux_do = account_config.linux_do

    # 检查是否有 linux_do 配置
    if not linux_do:
        print(f"❌ {account_name}: linux.do credentials not found for fuli wheel")
        return None

    username = linux_do.get("username")
    password = linux_do.get("password")

    if not username or not password:
        print(f"❌ {account_name}: linux.do username or password not found")
        return None

    # 带重试机制的浏览器登录
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if attempt > 1:
                print(f"ℹ️ {account_name}: Retry attempt {attempt}/{MAX_RETRIES} for fuli wheel")
                await asyncio.sleep(RETRY_DELAY)

            result = await _fuli_wheel_browser_impl(account_config, username, password)
            if result:
                return result
            else:
                last_error = "Browser operation returned no result"
                print(f"⚠️ {account_name}: Attempt {attempt} failed: {last_error}")

        except Exception as e:
            last_error = str(e)
            print(f"⚠️ {account_name}: Attempt {attempt} exception: {e}")

    print(f"❌ {account_name}: All {MAX_RETRIES} attempts failed for fuli wheel. Last error: {last_error}")
    return None


async def _fuli_wheel_browser_impl(account_config: "AccountConfig", username: str, password: str) -> dict | None:
    """fuli.hxi.me 大转盘浏览器操作实现"""
    import hashlib
    import os

    from camoufox.async_api import AsyncCamoufox

    from utils.browser_utils import take_screenshot
    from utils.linuxdo_session import LinuxDoSessionManager

    account_name = account_config.get_display_name()
    print(f"ℹ️ {account_name}: Starting fuli.hxi.me wheel lottery")

    # 尝试获取共享的 Linux.do 会话
    shared_session = LinuxDoSessionManager.get_cached_session(username)

    # 确定 storage_state 来源：优先使用共享会话
    storage_state_dir = "storage-states"
    os.makedirs(storage_state_dir, exist_ok=True)

    if shared_session:
        cache_file_path = shared_session.get_storage_state_path()
        print(f"ℹ️ {account_name}: Using shared Linux.do session for fuli wheel")
    else:
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        cache_file_path = f"{storage_state_dir}/fuli_wheel_linuxdo_{username_hash}_storage_state.json"
        print(f"ℹ️ {account_name}: No shared session, using standalone cache for fuli wheel")

    try:
        async with AsyncCamoufox(
            headless=True,
            humanize=True,
            locale="zh-CN",
        ) as browser:
            # 加载缓存的 storage state
            storage_state = cache_file_path if os.path.exists(cache_file_path) else None
            if storage_state:
                print(f"ℹ️ {account_name}: Found cache file, restoring storage state")
            else:
                print(f"ℹ️ {account_name}: No cache file found, starting fresh")

            context = await browser.new_context(storage_state=storage_state)
            page = await context.new_page()

            try:
                # 1. 先登录 linux.do
                print(f"ℹ️ {account_name}: Navigating to linux.do")
                await page.goto("https://linux.do/login", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                await page.wait_for_timeout(1500)

                current_url = page.url
                if "linux.do/login" in current_url:
                    print(f"ℹ️ {account_name}: Logging in to linux.do")
                    # 等待登录表单加载
                    try:
                        await page.wait_for_selector("#login-account-name", timeout=TIMEOUT_ELEMENT_WAIT)
                    except Exception:
                        print(f"⚠️ {account_name}: Login form not found, page may be loading slowly")
                        await page.wait_for_timeout(2000)

                    await page.fill("#login-account-name", username, timeout=TIMEOUT_FILL)
                    await page.wait_for_timeout(500)
                    await page.fill("#login-account-password", password, timeout=TIMEOUT_FILL)
                    await page.wait_for_timeout(500)
                    await page.click("#login-button", timeout=TIMEOUT_CLICK)
                    # 等待登录完成
                    try:
                        await page.wait_for_selector(".current-user", timeout=15000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    current_url = page.url
                    if "linux.do/login" in current_url:
                        print(f"❌ {account_name}: Failed to login to linux.do")
                        await take_screenshot(page, "fuli_wheel_login_failed", account_name)
                        return None

                    print(f"✅ {account_name}: Logged in to linux.do")
                    await context.storage_state(path=cache_file_path)
                else:
                    print(f"✅ {account_name}: Already logged in to linux.do (via cache)")

                # 2. 访问福利站大转盘页面
                print(f"ℹ️ {account_name}: Navigating to fuli.hxi.me/wheel")
                await page.goto("https://fuli.hxi.me/wheel", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                await page.wait_for_timeout(2000)

                # 3. 检查是否需要登录福利站
                login_btn = await page.query_selector('button:has-text("登录"), a:has-text("登录")')
                if login_btn:
                    print(f"ℹ️ {account_name}: Clicking login button on fuli.hxi.me")
                    await login_btn.click()
                    # 等待跳转到 OAuth 页面
                    try:
                        await page.wait_for_url("**connect.linux.do**", timeout=10000)
                    except Exception:
                        await page.wait_for_timeout(2000)

                    # 检查是否在 OAuth 授权页面
                    current_url = page.url
                    if "connect.linux.do" in current_url and "oauth2/authorize" in current_url:
                        print(f"ℹ️ {account_name}: At OAuth authorization page")
                        try:
                            await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=TIMEOUT_ELEMENT_WAIT)
                            allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                            if allow_btn:
                                print(f"ℹ️ {account_name}: Clicking authorize button")
                                await allow_btn.click()
                                await page.wait_for_timeout(2000)
                        except Exception as e:
                            print(f"⚠️ {account_name}: OAuth approve failed: {e}")

                    # 保存登录状态
                    await context.storage_state(path=cache_file_path)
                    print(f"✅ {account_name}: Logged in to fuli.hxi.me")

                # 4. 确保在转盘页面
                if "wheel" not in page.url:
                    await page.goto("https://fuli.hxi.me/wheel", wait_until="domcontentloaded", timeout=TIMEOUT_PAGE_LOAD)
                    await page.wait_for_timeout(1500)

                # 5. 获取 cookies 用于 API 调用
                cookies = await context.cookies()
                cookie_dict = {c["name"]: c["value"] for c in cookies if "fuli.hxi.me" in c.get("domain", "")}

                if "session" not in cookie_dict:
                    print(f"❌ {account_name}: Session cookie not found")
                    await take_screenshot(page, "fuli_wheel_no_session", account_name)
                    return None

                # 6. 调用抽奖 API
                return await _execute_fuli_wheel_spins(account_name, cookie_dict)

            except Exception as e:
                print(f"❌ {account_name}: Error in fuli wheel process: {e}")
                await take_screenshot(page, "fuli_wheel_error", account_name)
                return None
            finally:
                await page.close()
                await context.close()

    except Exception as e:
        print(f"❌ {account_name}: Error starting browser: {e}")
        return None


async def _execute_fuli_wheel_spins(account_name: str, cookies: dict) -> dict | None:
    """使用 cookies 执行 fuli.hxi.me 大转盘抽奖

    Returns:
        dict | None: 成功返回 {"type": "wheel_success", "total_quota": 总额度, "spin_count": 抽奖次数}
    """

    headers = {
        "accept": "*/*",
        "accept-language": "zh-CN,zh;q=0.9",
        "origin": "https://fuli.hxi.me",
        "referer": "https://fuli.hxi.me/wheel",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    }

    # 构建 cookie 字符串
    cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
    headers["cookie"] = cookie_str

    try:
        client = httpx.Client(http2=False, timeout=30.0)
        try:
            # 先检查剩余次数和今天的抽奖信息
            status_resp = client.get("https://fuli.hxi.me/api/wheel/status", headers=headers)
            remaining = 2  # 默认 2 次
            today_quota = 0  # 今天已获得的额度
            today_spins = 0  # 今天已抽的次数

            if status_resp.status_code == 200:
                status_data = response_resolve(status_resp, "get_wheel_status", account_name)
                if status_data:
                    remaining = status_data.get("remaining", 2)
                    # 尝试获取今天的抽奖信息（如果 API 返回的话）
                    today_quota = status_data.get("today_quota", status_data.get("todayQuota", 0))
                    today_spins = status_data.get("today_spins", status_data.get("todaySpins", 0))
                    # 如果没有 today_spins，根据 remaining 推算（假设每天 2 次）
                    if today_spins == 0 and remaining < 2:
                        today_spins = 2 - remaining
                    print(f"ℹ️ {account_name}: Wheel spins remaining: {remaining}, today spins: {today_spins}, today quota: {today_quota}")

            if remaining <= 0:
                print(f"ℹ️ {account_name}: No wheel spins remaining today")
                return {"type": "wheel_success", "total_quota": today_quota, "spin_count": today_spins, "already_done": True}

            # 执行抽奖
            total_quota = 0
            spin_count = 0

            while remaining > 0:
                spin_count += 1
                print(f"ℹ️ {account_name}: Spinning wheel #{spin_count}...")

                response = client.post("https://fuli.hxi.me/api/wheel", headers=headers)

                if response.status_code == 200:
                    data = response_resolve(response, "execute_wheel_spin", account_name)
                    if data and data.get("success"):
                        prize = data.get("prize", "")
                        quota = data.get("quota", 0)
                        remaining = data.get("remaining", remaining - 1)
                        total_quota += quota
                        print(f"✅ {account_name}: Spin #{spin_count} won {prize}! Quota: {quota}, remaining: {remaining}")
                    else:
                        error_msg = data.get("message", "Unknown error") if data else "No response"
                        print(f"❌ {account_name}: Spin #{spin_count} failed: {error_msg}")
                        break
                else:
                    print(f"❌ {account_name}: Spin #{spin_count} request failed with status {response.status_code}")
                    break

            if spin_count > 0:
                print(f"✅ {account_name}: Wheel lottery completed! Total quota earned: {total_quota}")
                return {"type": "wheel_success", "total_quota": total_quota, "spin_count": spin_count}

            return None

        finally:
            client.close()

    except Exception as e:
        print(f"❌ {account_name}: Error executing wheel spins: {e}")
        return None
