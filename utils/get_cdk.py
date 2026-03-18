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
    proxy = account_config.proxy or account_config.get('global_proxy')
    http_proxy = proxy_resolve(proxy) if proxy else None

    if access_token:
        print(f"ℹ️ {account_name}: Trying existing access_token for x666 checkin")
        result = await _execute_x666_checkin_with_token(account_name, access_token, http_proxy)
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
    shared_session_state = await shared_session.get_storage_state()
    print(f"ℹ️ {account_name}: Using shared Linux.do session for x666")

    try:
        async with AsyncCamoufox(
            headless=True,
            humanize=True,
            locale="en-US",
        ) as browser:
            def load_storage_state(source: dict | str | None) -> dict | None:
                if isinstance(source, dict):
                    return source
                if not source or not os.path.exists(source):
                    return None
                try:
                    with open(source, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except Exception as load_err:
                    print(f"⚠️ {account_name}: Failed to load storage state {source}: {load_err}")
                    return None

            def merge_storage_states(shared_source: dict | str | None, x666_source: dict | str | None) -> dict | str | None:
                shared_state = load_storage_state(shared_source)
                x666_state = load_storage_state(x666_source)

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
                if isinstance(shared_source, str) and os.path.exists(shared_source):
                    return shared_source
                if isinstance(x666_source, str) and os.path.exists(x666_source):
                    return x666_source
                return None

            # 共享 Linux.do 会话必须优先级更高，避免旧 x666 缓存覆盖新会话
            storage_state = merge_storage_states(shared_session_state or cache_file_path, x666_cache_file_path)
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
                    print(f"ℹ️ {account_name}: x666 fallback login current URL after goto: {current_url}")
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
                    print(f"ℹ️ {account_name}: x666 fallback clicked Linux.do login button")
                    try:
                        await page.wait_for_selector('.current-user', timeout=15000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    post_login_guard = await detect_linuxdo_page_guard(page)
                    print(f"ℹ️ {account_name}: x666 fallback login URL after submit: {page.url}")
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

                async def handle_sso_provider_page() -> str:
                    print(f"ℹ️ {account_name}: x666 OAuth reached linux.do/session/sso_provider, waiting for redirect")
                    # 第一阶段：等待自动跳转（sso_provider 通常会自动 POST 并跳走）
                    try:
                        await page.wait_for_url('**connect.linux.do/**', timeout=12000)
                        return page.url
                    except Exception:
                        pass
                    try:
                        await page.wait_for_url('**up.x666.me/**', timeout=5000)
                        return page.url
                    except Exception:
                        pass

                    current_url = page.url
                    if 'linux.do/session/sso_provider' not in current_url:
                        return current_url

                    # 第二阶段：尝试 JS 点击/提交
                    print(f"⚠️ {account_name}: sso_provider did not auto-redirect, trying generic submit/click handlers")
                    handled = await page.evaluate("""() => {
                        const textMatches = (el) => {
                            const text = (el.innerText || el.textContent || el.value || '').trim();
                            return /允许|继续|authorize|continue|approve|sign in/i.test(text);
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
                    print(f"ℹ️ {account_name}: x666 sso_provider handler result: {handled}")

                    # noop 说明页面没有可操作元素，尝试直接 fetch POST sso_provider 表单
                    if handled == 'noop':
                        print(f"ℹ️ {account_name}: No clickable element found, trying fetch POST to sso_provider")
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
                            print(f"ℹ️ {account_name}: fetch POST result: {post_result}")
                        except Exception as fetch_err:
                            print(f"⚠️ {account_name}: fetch POST failed: {fetch_err}")

                    # 等待跳转，超时缩短为 15s 避免长时间阻塞
                    try:
                        await page.wait_for_url('**connect.linux.do/**', timeout=15000)
                        return page.url
                    except Exception:
                        pass
                    try:
                        await page.wait_for_url('**up.x666.me/**', timeout=10000)
                        return page.url
                    except Exception:
                        pass

                    current_url = page.url
                    print(f"ℹ️ {account_name}: URL after sso_provider handler: {current_url}")
                    if 'linux.do/session/sso_provider' in current_url:
                        await save_page_content_to_file(page, 'x666_sso_provider_stuck', account_name, prefix='x666')
                        await take_screenshot(page, 'x666_sso_provider_stuck', account_name)
                    return current_url

                print(f"ℹ️ {account_name}: Checking x666 token state on up.x666.me")
                await page.goto('https://up.x666.me', wait_until='domcontentloaded', timeout=TIMEOUT_PAGE_LOAD)
                await page.wait_for_timeout(1500)

                token = await get_valid_token_from_page()
                if token:
                    print(f"✅ {account_name}: Reusing valid token from x666 page cache")
                    await context.storage_state(path=x666_cache_file_path)
                    _proxy = account_config.proxy or account_config.get('global_proxy')
                    _http_proxy = proxy_resolve(_proxy) if _proxy else None
                    return await _execute_x666_checkin_with_token(account_name, token, _http_proxy)

                print(f"ℹ️ {account_name}: Shared Linux.do session is ready, starting x666 OAuth")
                auth_url = await get_auth_url()
                if not auth_url:
                    await save_page_content_to_file(page, 'x666_auth_url_missing', account_name, prefix='x666')
                    await take_screenshot(page, 'x666_auth_url_missing', account_name)
                    return None

                for flow_round in range(1, 5):
                    if flow_round > 1:
                        print(f"ℹ️ {account_name}: Continuing x666 OAuth flow round {flow_round}")

                    # 等待页面加载并给 sso_provider 的 JS 足够时间自动提交
                    try:
                        await page.goto(auth_url, wait_until='networkidle', timeout=TIMEOUT_PAGE_LOAD)
                    except Exception:
                        # networkidle 可能超时，降级为 domcontentloaded + 额外等待
                        try:
                            await page.goto(auth_url, wait_until='domcontentloaded', timeout=TIMEOUT_PAGE_LOAD)
                        except Exception:
                            pass
                        await page.wait_for_timeout(3000)
                    current_url = page.url
                    print(f"ℹ️ {account_name}: x666 OAuth current URL: {current_url}")

                    if 'linux.do/login' in current_url:
                        print(f"ℹ️ {account_name}: x666 OAuth redirected to Linux.do login")
                        login_ok = await ensure_linuxdo_login()
                        if not login_ok:
                            return None
                        continue

                    if 'linux.do/session/sso_provider' in current_url:
                        current_url = await handle_sso_provider_page()
                        # sso_provider 卡住且页面为空，说明 linux.do session 已失效，需重新登录
                        if 'linux.do/session/sso_provider' in current_url:
                            print(f"ℹ️ {account_name}: sso_provider stuck, trying to re-login linux.do")
                            login_ok = await ensure_linuxdo_login()
                            print(f"ℹ️ {account_name}: x666 fallback re-login result: {login_ok}")
                            if not login_ok:
                                return None
                            # 重新获取 auth_url，旧的 state 已失效
                            auth_url = await get_auth_url()
                            print(f"ℹ️ {account_name}: x666 fallback refreshed auth_url: {'present' if auth_url else 'missing'}")
                            if not auth_url:
                                return None
                            continue

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
                        await page.wait_for_url('**up.x666.me/**', timeout=20000)
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
                        _proxy = account_config.proxy or account_config.get('global_proxy')
                        _http_proxy = proxy_resolve(_proxy) if _proxy else None
                        return await _execute_x666_checkin_with_token(account_name, token, _http_proxy)

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
        client = httpx.Client(http2=True, timeout=30.0, proxy=http_proxy)
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
                            balance = status_data.get('current_quota', status_data.get('balance', 0))
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
