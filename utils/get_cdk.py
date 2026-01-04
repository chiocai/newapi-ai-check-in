#!/usr/bin/env python3
"""
CDK 获取模块

提供各个 provider 的 CDK 获取函数
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from utils.http_utils import proxy_resolve, response_resolve

if TYPE_CHECKING:
    from utils.config import AccountConfig


def get_runawaytime_checkin_cdk(account_config: "AccountConfig") -> str | None:
    """获取 runawaytime 签到 CDK
    
    通过 fuli.hxi.me 签到获取 CDK
    
    Args:
        account_config: 账号配置对象，需要包含 fuli_cookies 在 extra 中
    
    Returns:
        str | None: CDK 字符串，如果获取失败则返回 None
    """
    account_name = account_config.get_display_name()
    fuli_cookies = account_config.get("fuli_cookies")
    proxy = account_config.proxy or account_config.get("global_proxy")
    
    if not fuli_cookies:
        print(f"❌ {account_name}: fuli_cookies not found in account config")
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


def get_runawaytime_wheel_cdk(account_config: "AccountConfig") -> list[str] | None:
    """获取 runawaytime 大转盘 CDK
    
    通过 fuli.hxi.me 大转盘获取 CDK，支持多次转盘
    
    Args:
        account_config: 账号配置对象，需要包含 fuli_cookies 在 extra 中
    
    Returns:
        list[str] | None: CDK 字符串列表，如果获取失败则返回 None
    """
    account_name = account_config.get_display_name()
    fuli_cookies = account_config.get("fuli_cookies")
    proxy = account_config.proxy or account_config.get("global_proxy")
    
    if not fuli_cookies:
        print(f"❌ {account_name}: fuli_cookies not found in account config")
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
    """异步获取 b4u 大转盘抽奖 CDK

    使用 Camoufox 浏览器自动化完成整个流程
    福利站使用 Next-Auth，OAuth 流程：
    1. GET /api/auth/csrf → 获取 CSRF token
    2. POST /api/auth/signin/linuxdo → 触发 LinuxDo OAuth
    3. 跳转到 connect.linux.do/oauth2/authorize 授权
    4. 回调 /api/auth/callback/linuxdo?code=xxx
    5. POST /luckydraw → 执行抽奖
    """
    import hashlib
    import os
    from camoufox.async_api import AsyncCamoufox
    from utils.browser_utils import take_screenshot

    account_name = account_config.get_display_name()
    linux_do = account_config.linux_do
    proxy = account_config.proxy or account_config.get("global_proxy")

    if not linux_do:
        print(f"❌ {account_name}: linux.do credentials not found in account config for b4u")
        return None

    username = linux_do.get("username")
    password = linux_do.get("password")

    if not username or not password:
        print(f"❌ {account_name}: linux.do username or password not found")
        return None

    # 生成缓存文件路径
    storage_state_dir = "storage-states"
    os.makedirs(storage_state_dir, exist_ok=True)
    username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
    cache_file_path = f"{storage_state_dir}/b4u_linuxdo_{username_hash}_storage_state.json"

    print(f"ℹ️ {account_name}: Starting Camoufox browser to get b4u CDK")

    try:
        async with AsyncCamoufox(
            headless=True,
            humanize=True,
            locale="zh-CN",
            geoip=True if proxy else False,
            proxy=proxy,
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
                # 1. 访问福利站大转盘页面
                print(f"ℹ️ {account_name}: Navigating to b4u luckydraw page")
                await page.goto("https://tw.b4u.qzz.io/luckydraw", wait_until="domcontentloaded")
                await page.wait_for_timeout(5000)  # 等待 Cloudflare 验证

                # 2. 检查是否需要登录
                current_url = page.url
                is_logged_in = False

                # 如果被重定向到登录页，说明未登录
                if "/login" in current_url:
                    print(f"ℹ️ {account_name}: Redirected to login page, need to authenticate")
                else:
                    # 检查页面是否有抽奖按钮
                    try:
                        spin_btn = await page.query_selector('button:has-text("开始抽奖")')
                        if spin_btn:
                            is_logged_in = True
                            print(f"✅ {account_name}: Already logged in to b4u via cache")
                    except Exception:
                        pass

                # 3. 如果未登录，执行 LinuxDo OAuth 登录
                if not is_logged_in:
                    print(f"ℹ️ {account_name}: Not logged in, starting LinuxDo OAuth flow")

                    # 确保在登录页面
                    if "/login" not in page.url:
                        await page.goto("https://tw.b4u.qzz.io/login", wait_until="domcontentloaded")
                        await page.wait_for_timeout(3000)

                    # 查找并点击 LinuxDo 登录按钮 - 尝试多种选择器
                    login_btn = None
                    selectors = [
                        'button:has-text("使用 Linux.do 登录")',  # tw.b4u.qzz.io 的按钮文本
                        'button:has-text("Linux.do")',
                        'button:has-text("LinuxDo")',
                        'button:has-text("LINUX DO")',
                        'a:has-text("LinuxDo")',
                        'a:has-text("LINUX DO")',
                        '[data-provider="linuxdo"]',
                    ]

                    for selector in selectors:
                        try:
                            login_btn = await page.query_selector(selector)
                            if login_btn:
                                btn_text = await login_btn.inner_text()
                                print(f"ℹ️ {account_name}: Found login button with selector '{selector}': {btn_text}")
                                break
                        except Exception:
                            continue

                    # 截图当前登录页面状态（用于调试）
                    await take_screenshot(page, "b4u_login_page", account_name)

                    # 获取页面上所有可点击元素信息
                    clickables_info = await page.evaluate("""() => {
                        const elements = document.querySelectorAll('button, a, input[type="submit"], [role="button"]');
                        return Array.from(elements).map(el => ({
                            tag: el.tagName,
                            text: (el.innerText || el.value || '').trim().substring(0, 50),
                            href: el.href || '',
                            class: el.className,
                            id: el.id
                        })).filter(e => e.text || e.href);
                    }""")
                    print(f"ℹ️ {account_name}: Clickable elements on login page: {clickables_info}")

                    # 查找 LinuxDo OAuth 链接（可能是 a 标签而不是 button）
                    linuxdo_link = None
                    link_selectors = [
                        'a[href*="linuxdo"]',
                        'a[href*="linux.do"]',
                        'a[href*="signin/linuxdo"]',
                        'a[href*="auth/signin"]',
                    ]

                    for selector in link_selectors:
                        try:
                            linuxdo_link = await page.query_selector(selector)
                            if linuxdo_link:
                                href = await linuxdo_link.get_attribute("href")
                                print(f"ℹ️ {account_name}: Found LinuxDo link with selector '{selector}': {href}")
                                break
                        except Exception:
                            continue

                    if linuxdo_link:
                        print(f"ℹ️ {account_name}: Clicking LinuxDo link...")
                        await linuxdo_link.click()
                        await page.wait_for_timeout(5000)
                    elif login_btn:
                        print(f"ℹ️ {account_name}: Clicking LinuxDo login button...")
                        await login_btn.click()
                        await page.wait_for_timeout(5000)
                    else:
                        print(f"⚠️ {account_name}: No suitable login button/link found")

                    # 检查是否跳转到 linux.do 登录页面
                    current_url = page.url
                    print(f"ℹ️ {account_name}: Current URL after login click: {current_url}")

                    # 处理 linux.do 登录
                    if "linux.do/login" in current_url:
                        print(f"ℹ️ {account_name}: At linux.do login page, filling credentials")
                        try:
                            await page.fill("#login-account-name", username)
                            await page.wait_for_timeout(1000)
                            await page.fill("#login-account-password", password)
                            await page.wait_for_timeout(1000)
                            await page.click("#login-button")
                            await page.wait_for_timeout(10000)
                        except Exception as e:
                            print(f"❌ {account_name}: Failed to fill login form: {e}")
                            await take_screenshot(page, "b4u_login_failed", account_name)
                            return None

                    # 检查是否需要授权
                    current_url = page.url
                    if "connect.linux.do" in current_url and "oauth2/authorize" in current_url:
                        print(f"ℹ️ {account_name}: At OAuth authorization page")
                        try:
                            await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
                            allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                            if allow_btn:
                                print(f"ℹ️ {account_name}: Clicking authorize button")
                                await allow_btn.click()
                                await page.wait_for_timeout(5000)
                        except Exception as e:
                            print(f"⚠️ {account_name}: OAuth approve failed: {e}")

                    # 等待回调完成
                    await page.wait_for_timeout(3000)

                    # 保存会话状态
                    await context.storage_state(path=cache_file_path)
                    print(f"✅ {account_name}: Storage state saved to cache file")

                    # 确保回到抽奖页面
                    current_url = page.url
                    if "luckydraw" not in current_url:
                        print(f"ℹ️ {account_name}: Navigating back to luckydraw page")
                        await page.goto("https://tw.b4u.qzz.io/luckydraw", wait_until="domcontentloaded")
                        await page.wait_for_timeout(3000)

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
                while remaining > 0:
                    # 查找开始抽奖按钮
                    spin_btn = await page.query_selector('button:has-text("开始抽奖")')
                    if not spin_btn:
                        print(f"⚠️ {account_name}: Spin button not found")
                        break

                    # 检查按钮是否可点击
                    is_disabled = await spin_btn.get_attribute("disabled")
                    if is_disabled:
                        print(f"ℹ️ {account_name}: Spin button is disabled")
                        break

                    # 点击抽奖
                    spin_count += 1
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

                    # 关闭结果弹窗
                    try:
                        close_btn = await page.query_selector('button:has-text("确定"), button:has-text("关闭"), button:has-text("OK")')
                        if close_btn:
                            await close_btn.click()
                            await page.wait_for_timeout(1000)
                    except Exception:
                        pass

                    remaining -= 1
                    # 短暂等待后继续下一次
                    await page.wait_for_timeout(2000)

                print(f"ℹ️ {account_name}: Lottery completed - {spin_count} spins, {prize_count} prizes")

                # 访问"我的兑换码"页面获取今日所有 CDK（统一从这里获取，而不是从转盘结果）
                print(f"ℹ️ {account_name}: Checking my-codes page for today's CDKs")
                await page.goto("https://tw.b4u.qzz.io/my-codes", wait_until="domcontentloaded")
                await page.wait_for_timeout(3000)

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

                # 从页面提取今天的 CDK（无论是否已兑换，由主站API判断）
                # 根据页面结构：表格列为 ['兑换码', '面额', '来源', '获取时间', '操作']
                # 使用北京时间 (UTC+8) 判断"今天"
                today_cdks = await page.evaluate("""() => {
                    const cdks = [];
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
                            const time = cells[3].innerText.trim();  // 获取时间列

                            // 检查是否是有效的 CDK 格式且是今天的
                            if (cdk && /^[a-f0-9]{32}$/i.test(cdk) && time.startsWith(todayStr)) {
                                cdks.push(cdk);
                            }
                        }
                    }

                    return { cdks, todayStr };
                }""")

                beijing_today = today_cdks.get('todayStr', 'unknown')
                today_cdk_list = today_cdks.get('cdks', [])
                print(f"ℹ️ {account_name}: Beijing time today: {beijing_today}")
                print(f"ℹ️ {account_name}: Found {len(today_cdk_list)} CDK(s) from today on my-codes page")

                if today_cdk_list:
                    print(f"✅ {account_name}: Total {len(today_cdk_list)} CDK(s) to redeem")
                    return today_cdk_list
                else:
                    print(f"ℹ️ {account_name}: No CDKs from today found on my-codes page")
                    return None

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
    """获取 x666 抽奖 CDK

    通过 qd.x666.me 抽奖获取 CDK

    Args:
        account_config: 账号配置对象，需要包含 access_token 在 extra 中

    Returns:
        str | None: CDK 字符串，如果获取失败则返回 None
    """
    account_name = account_config.get_display_name()
    access_token = account_config.get("access_token")
    proxy = account_config.proxy or account_config.get("global_proxy")
    
    if not access_token:
        print(f"❌ {account_name}: access_token not found in account config")
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
            
            client.cookies.set("i18next", "en")
            
            # 先获取用户信息，检查是否可以抽奖
            info_headers = headers.copy()
            info_headers.update({
                "authorization": f"Bearer {access_token}",
                "content-length": "0",
                "content-type": "application/json",
                "origin": "https://qd.x666.me",
                "referer": "https://qd.x666.me/",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            })
            
            info_response = client.post(
                "https://qd.x666.me/api/user/info",
                headers=info_headers,
                timeout=30
            )
            
            if info_response.status_code == 200:
                info_data = response_resolve(info_response, "get_user_info", account_name)
                if info_data and info_data.get("success"):
                    data = info_data.get("data", {})
                    can_spin = data.get("can_spin", False)
                    
                    if not can_spin:
                        # 今天已经抽过，返回已有的 CDK
                        today_record = data.get("today_record")
                        if today_record:
                            existing_cdk = today_record.get("cdk", "")
                            if existing_cdk:
                                print(f"✅ {account_name}: Already spun today, existing CDK: {existing_cdk}")
                                return existing_cdk
                        print(f"ℹ️ {account_name}: Already spun today, no CDK available")
                        return None
            
            # 执行抽奖
            spin_headers = headers.copy()
            spin_headers.update({
                "authorization": f"Bearer {access_token}",
                "content-length": "0",
                "content-type": "application/json",
                "origin": "https://qd.x666.me",
                "referer": "https://qd.x666.me/",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            })
            
            response = client.post(
                "https://qd.x666.me/api/lottery/spin",
                headers=spin_headers,
                timeout=30
            )
            
            if response.status_code in [200, 400]:
                json_data = response_resolve(response, "execute_spin", account_name)
                if json_data is None:
                    return None
                
                if json_data.get("success"):
                    data = json_data.get("data", {})
                    cdk = data.get("cdk", "")
                    if cdk:
                        label = data.get("label", "Unknown")
                        print(f"✅ {account_name}: Spin successful! Prize: {label}, CDK: {cdk}")
                        return cdk
                
                message = json_data.get("message", json_data.get("msg", ""))
                if "already" in message.lower() or "已经" in message or "已抽" in message:
                    print(f"✅ {account_name}: Already spun today")
                    return None
                
                print(f"❌ {account_name}: Spin failed - {message}")
            
            return None
        finally:
            client.close()
    except Exception as e:
        print(f"❌ {account_name}: Error getting x666 CDK - {e}")
        return None