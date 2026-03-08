#!/usr/bin/env python3
"""
浏览器自动化相关的公共工具函数
"""

import os
import random
from datetime import datetime
from urllib.parse import urlparse


def parse_cookies(cookies_data) -> dict:
    """解析 cookies 数据

    支持字典格式和字符串格式的 cookies

    Args:
        cookies_data: cookies 数据，可以是字典或分号分隔的字符串

    Returns:
        解析后的 cookies 字典
    """
    if isinstance(cookies_data, dict):
        return cookies_data

    if isinstance(cookies_data, str):
        cookies_dict = {}
        for cookie in cookies_data.split(";"):
            if "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                cookies_dict[key] = value
        return cookies_dict
    return {}


def filter_cookies(cookies: list[dict], origin: str, verbose: bool = False) -> dict:
    """根据 origin 过滤 cookies，只保留匹配域名的 cookies

    Args:
        cookies: Camoufox cookies 列表，每个元素是包含 name, value, domain 等的字典
        origin: Provider 的 origin URL (例如: https://api.example.com)
        verbose: 是否打印详细的过滤日志（默认 False，只打印匹配的 cookies）

    Returns:
        过滤后的 cookies 字典 {name: value}
    """
    # 提取 provider origin 的域名
    provider_domain = urlparse(origin).netloc

    # 过滤 cookies，只保留与 provider domain 匹配的
    user_cookies = {}
    filtered_count = 0
    total_count = 0

    for cookie in cookies:
        cookie_name = cookie.get("name")
        cookie_value = cookie.get("value")
        cookie_domain = cookie.get("domain", "")
        total_count += 1

        if cookie_name and cookie_value:
            # 检查 cookie domain 是否匹配 provider domain
            # cookie domain 可能以 . 开头 (如 .example.com)，需要处理
            normalized_cookie_domain = cookie_domain.lstrip(".")
            normalized_provider_domain = provider_domain.lstrip(".")

            # 匹配逻辑：cookie domain 应该是 provider domain 的后缀
            if (
                normalized_provider_domain == normalized_cookie_domain
                or normalized_provider_domain.endswith("." + normalized_cookie_domain)
                or normalized_cookie_domain.endswith("." + normalized_provider_domain)
            ):
                user_cookies[cookie_name] = cookie_value
                if verbose:
                    print(f"  🔵 Matched cookie: {cookie_name} (domain: {cookie_domain})")
            else:
                filtered_count += 1
                if verbose:
                    print(f"  🔴 Filtered cookie: {cookie_name} (domain: {cookie_domain})")

    print(
        f"🔍 Cookie filtering: {len(user_cookies)} matched from {total_count} total "
        f"(provider: {provider_domain})"
    )

    return user_cookies


def get_random_user_agent() -> str:
    """获取随机的现代浏览器 User Agent 字符串

    Returns:
        随机选择的 User Agent 字符串
    """
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) " "Gecko/20100101 Firefox/134.0",
    ]
    return random.choice(user_agents)


async def take_screenshot(
    page,
    reason: str,
    account_name: str,
    screenshots_dir: str = "screenshots",
) -> None:
    """截取当前页面的屏幕截图

    Args:
        page: Camoufox/Playwright 页面对象
        reason: 截图原因描述
        account_name: 账号名称（用于日志输出和文件名）
        screenshots_dir: 截图保存目录，默认为 "screenshots"
    """
    try:
        os.makedirs(screenshots_dir, exist_ok=True)

        # 自动生成安全的账号名称
        safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)

        # 生成文件名: 账号名_时间戳_原因.png
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_reason = "".join(c if c.isalnum() else "_" for c in reason)
        filename = f"{safe_account_name}_{timestamp}_{safe_reason}.png"
        filepath = os.path.join(screenshots_dir, filename)

        await page.screenshot(path=filepath, full_page=True)
        print(f"📸 {account_name}: Screenshot saved to {filepath}")
    except Exception as e:
        print(f"⚠️ {account_name}: Failed to take screenshot: {e}")


async def save_page_content_to_file(
    page,
    reason: str,
    account_name: str,
    prefix: str = "",
    logs_dir: str = "logs",
) -> None:
    """保存页面 HTML 到日志文件

    Args:
        page: Camoufox/Playwright 页面对象
        reason: 日志原因描述
        account_name: 账号名称（用于日志输出和文件名）
        prefix: 文件名前缀（如 "github_", "linuxdo_" 等）
        logs_dir: 日志保存目录，默认为 "logs"
    """
    try:
        os.makedirs(logs_dir, exist_ok=True)

        # 自动生成安全的账号名称
        safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_reason = "".join(c if c.isalnum() else "_" for c in reason)
        
        # 构建文件名
        if prefix:
            filename = f"{safe_account_name}_{timestamp}_{prefix}_{safe_reason}.html"
        else:
            filename = f"{safe_account_name}_{timestamp}_{safe_reason}.html"
        filepath = os.path.join(logs_dir, filename)

        html_content = await page.content()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"📄 {account_name}: Page HTML saved to {filepath}")
    except Exception as e:
        print(f"⚠️ {account_name}: Failed to save HTML: {e}")


async def aliyun_captcha_check(page, account_name: str) -> bool:
    """阿里云验证码检查和处理

    检查页面是否有阿里云验证码（通过 traceid 检测），如果有则尝试自动滑动验证

    Args:
        page: Camoufox/Playwright 页面对象
        account_name: 账号名称（用于日志输出）

    Returns:
        bool: 验证码处理是否成功（无验证码或验证通过返回 True，验证失败返回 False）
    """
    # 检查是否有 traceid (阿里云验证码页面)
    try:
        traceid = await page.evaluate(
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

        if traceid:
            print(f"⚠️ {account_name}: Aliyun captcha detected, traceid: {traceid}")
            try:
                await page.wait_for_selector("#nocaptcha", timeout=60000)

                slider_element = await page.query_selector("#nocaptcha .nc_scale")
                if slider_element:
                    slider = await slider_element.bounding_box()
                    print(f"ℹ️ {account_name}: Slider bounding box: {slider}")

                slider_handle = await page.query_selector("#nocaptcha .btn_slide")
                if slider_handle:
                    handle = await slider_handle.bounding_box()
                    print(f"ℹ️ {account_name}: Slider handle bounding box: {handle}")

                if slider and handle:
                    await take_screenshot(page, "aliyun_captcha_slider_start", account_name)

                    await page.mouse.move(
                        handle.get("x") + handle.get("width") / 2,
                        handle.get("y") + handle.get("height") / 2,
                    )
                    await page.mouse.down()
                    await page.mouse.move(
                        handle.get("x") + slider.get("width"),
                        handle.get("y") + handle.get("height") / 2,
                        steps=2,
                    )
                    await page.mouse.up()
                    await take_screenshot(page, "aliyun_captcha_slider_completed", account_name)

                    # Wait for page to be fully loaded
                    await page.wait_for_timeout(20000)

                    await take_screenshot(page, "aliyun_captcha_slider_result", account_name)
                    return True
                else:
                    print(f"❌ {account_name}: Slider or handle not found")
                    await take_screenshot(page, "aliyun_captcha_error", account_name)
                    return False
            except Exception as e:
                print(f"❌ {account_name}: Error occurred while moving slider, {e}")
                await take_screenshot(page, "aliyun_captcha_error", account_name)
                return False
        else:
            print(f"ℹ️ {account_name}: No traceid found")
            await take_screenshot(page, "aliyun_captcha_traceid_found", account_name)
            return True
    except Exception as e:
        print(f"❌ {account_name}: Error occurred while getting traceid, {e}")
        await take_screenshot(page, "aliyun_captcha_error", account_name)
        return False


async def wait_for_linuxdo_login_ready(page, account_name: str, timeout: int = 45000) -> None:
    """等待 LinuxDo 登录页前端完全就绪

    LinuxDo 当前登录页是 Ember 单页应用，表单元素会先渲染出来，
    但登录按钮事件绑定可能稍后才完成。过早点击会停留在 `/login`，
    且不会真正发出登录请求。
    """
    await page.wait_for_selector('#login-account-name', timeout=timeout)
    await page.wait_for_function(
        """() => {
            return !!window.requirejs || !!window.Ember || !!document.querySelector('.ember-application');
        }""",
        timeout=timeout,
    )
    await page.wait_for_timeout(1500)
    print(f"ℹ️ {account_name}: LinuxDo login page is ready")


async def has_linuxdo_human_verification(page) -> bool:
    """检测 LinuxDo 登录页是否出现 Human Verification / hCaptcha"""
    snapshot = await get_linuxdo_human_verification_snapshot(page)
    return classify_linuxdo_human_verification_snapshot(snapshot)['present']


def classify_linuxdo_human_verification_snapshot(snapshot: dict) -> dict:
    """根据页面快照判断 LinuxDo Human Verification 状态"""
    token_values = [
        value.strip()
        for value in [
            snapshot.get('hcaptcha_response'),
            snapshot.get('grecaptcha_response'),
            snapshot.get('iframe_response'),
        ]
        if isinstance(value, str)
    ]
    has_token = any(token_values)

    present = bool(
        snapshot.get('has_hcaptcha_modal')
        or snapshot.get('has_hcaptcha_field')
        or snapshot.get('verify_button_present')
        or snapshot.get('iframe_count', 0) > 0
        or snapshot.get('human_verification_title')
    )

    return {
        'present': present,
        'solved': bool(present and has_token),
        'blocking': bool(present and not has_token),
        'sitekey': snapshot.get('sitekey'),
        'verify_button_disabled': bool(snapshot.get('verify_button_disabled')),
        'verify_button_present': bool(snapshot.get('verify_button_present')),
        'iframe_count': snapshot.get('iframe_count', 0),
        'token_present': has_token,
    }


async def get_linuxdo_human_verification_snapshot(page) -> dict:
    """采集 LinuxDo Human Verification 页面快照"""
    return await page.evaluate(
        """() => {
            const hcaptchaIframe =
                document.querySelector('iframe[data-hcaptcha-widget-id]') ||
                document.querySelector('iframe[src*="hcaptcha.com"]') ||
                document.querySelector('iframe[title*="hCaptcha"]');
            const verifyButton = Array.from(document.querySelectorAll('button'))
                .find(button => (button.innerText || '').trim().includes('Verify'));
            const hcaptchaResponse = document.querySelector('textarea[name="h-captcha-response"]');
            const grecaptchaResponse = document.querySelector('textarea[name="g-recaptcha-response"]');
            const modalTitle = document.querySelector('#discourse-modal-title');
            let sitekey = null;
            if (hcaptchaIframe) {
                const iframeSrc = hcaptchaIframe.getAttribute('src') || '';
                if (iframeSrc) {
                    try {
                        const iframeUrl = new URL(iframeSrc, window.location.href);
                        sitekey = iframeUrl.searchParams.get('sitekey');
                    } catch (e) {}
                }
            }
            return {
                has_hcaptcha_modal: !!document.querySelector('.hcaptcha-verify-modal'),
                has_hcaptcha_field: !!document.querySelector('#h-captcha-field'),
                human_verification_title: (modalTitle?.innerText || '').trim(),
                verify_button_present: !!verifyButton,
                verify_button_disabled: !!verifyButton?.disabled,
                iframe_count: document.querySelectorAll('iframe[data-hcaptcha-widget-id], iframe[src*="hcaptcha.com"], iframe[title*="hCaptcha"]').length,
                iframe_response: hcaptchaIframe?.getAttribute('data-hcaptcha-response') || '',
                hcaptcha_response: hcaptchaResponse?.value || '',
                grecaptcha_response: grecaptchaResponse?.value || '',
                sitekey,
            };
        }"""
    )


async def try_bypass_linuxdo_human_verification(page, account_name: str, timeout: int = 20000) -> dict:
    """尝试被动通过 LinuxDo Human Verification

    这里只做页面内的被动尝试：
    1. 检测现有 token
    2. 点击 hCaptcha 复选框 iframe
    3. 在按钮可用时点击 Verify

    不接入第三方打码服务；若仍失败则走降级分支。
    """
    initial_snapshot = await get_linuxdo_human_verification_snapshot(page)
    initial_state = classify_linuxdo_human_verification_snapshot(initial_snapshot)
    if not initial_state['present']:
        return {'present': False, 'solved': False, 'sitekey': None, 'reason': 'not_present'}
    if initial_state['solved']:
        print(f"✅ {account_name}: Human Verification token already present")
        return {'present': True, 'solved': True, 'sitekey': initial_state['sitekey'], 'reason': 'token_present'}

    print(
        f"⚠️ {account_name}: Human Verification detected"
        f"{', sitekey=' + initial_state['sitekey'] if initial_state['sitekey'] else ''}"
    )

    deadline = datetime.now().timestamp() + timeout / 1000
    iframe_click_count = 0
    verify_click_count = 0

    while datetime.now().timestamp() < deadline:
        snapshot = await get_linuxdo_human_verification_snapshot(page)
        state = classify_linuxdo_human_verification_snapshot(snapshot)
        if not state['present']:
            print(f"✅ {account_name}: Human Verification dialog disappeared")
            return {'present': True, 'solved': True, 'sitekey': state['sitekey'], 'reason': 'dialog_disappeared'}
        if state['solved']:
            print(f"✅ {account_name}: Human Verification token captured")
            return {'present': True, 'solved': True, 'sitekey': state['sitekey'], 'reason': 'token_captured'}

        if iframe_click_count < 2 and state['iframe_count'] > 0:
            iframe_locator = page.locator(
                'iframe[data-hcaptcha-widget-id], iframe[src*="hcaptcha.com"], iframe[title*="hCaptcha"]'
            ).first
            iframe = await iframe_locator.bounding_box()
            if iframe:
                await page.mouse.click(iframe['x'] + iframe['width'] / 2, iframe['y'] + iframe['height'] / 2)
                iframe_click_count += 1
                print(f"ℹ️ {account_name}: Clicked hCaptcha iframe center ({iframe_click_count}/2)")
                await page.wait_for_timeout(4000)
                continue

        if verify_click_count < 2 and snapshot.get('verify_button_present') and not snapshot.get('verify_button_disabled'):
            verify_button = page.get_by_role('button', name='Verify')
            if await verify_button.count():
                await verify_button.click()
                verify_click_count += 1
                print(f"ℹ️ {account_name}: Clicked Verify button ({verify_click_count}/2)")
                await page.wait_for_timeout(3000)
                continue

        await page.wait_for_timeout(1000)

    final_snapshot = await get_linuxdo_human_verification_snapshot(page)
    final_state = classify_linuxdo_human_verification_snapshot(final_snapshot)
    return {
        'present': final_state['present'],
        'solved': final_state['solved'],
        'sitekey': final_state['sitekey'],
        'reason': 'timeout',
        'verify_button_disabled': final_state['verify_button_disabled'],
        'iframe_count': final_state['iframe_count'],
    }


async def get_linuxdo_hcaptcha_response(page) -> str:
    """获取 LinuxDo 页面中的 hCaptcha 响应 token"""
    selectors = [
        'textarea[name="h-captcha-response"]',
        'input[name="h-captcha-response"]',
        'textarea[name="g-recaptcha-response"]',
        'input[name="g-recaptcha-response"]',
    ]
    for selector in selectors:
        locator = page.locator(selector)
        if await locator.count():
            try:
                value = await locator.first.input_value()
            except Exception:
                value = await locator.first.evaluate('(el) => el.value || el.textContent || ""')
            if value:
                return value
    return ''


def detect_linuxdo_page_guard_from_text(text: str) -> dict:
    """从页面文本中检测 LinuxDo 的拦截类型"""
    normalized = (text or '').lower()
    return {
        'human_verification': any(
            keyword in normalized
            for keyword in [
                'human verification',
                'hcaptcha',
                'h-captcha',
                'turnstile 正在检查用户环境',
            ]
        ),
        'human_verification_sitekey': None,
        'cloudflare_challenge': any(
            keyword in normalized
            for keyword in [
                'just a moment',
                'checking your browser',
                '/cdn-cgi/challenge-platform/',
                'challenge-platform',
            ]
        ),
        'high_load': any(
            keyword in normalized
            for keyword in [
                'server is currently experiencing high load',
                'please try again later',
                'server is too busy',
                'too many requests',
                'rate limited',
                'rate limit exceeded',
            ]
        ),
    }


async def detect_linuxdo_page_guard(page) -> dict:
    """检测当前 LinuxDo 页面是否被验证码或挑战页拦截"""
    try:
        page_text = await page.locator('body').inner_text()
    except Exception:
        page_text = ''

    result = detect_linuxdo_page_guard_from_text(page_text)

    snapshot = await get_linuxdo_human_verification_snapshot(page)
    state = classify_linuxdo_human_verification_snapshot(snapshot)
    if state['present']:
        result['human_verification'] = True
        result['human_verification_sitekey'] = state.get('sitekey')
        result['human_verification_solved'] = state.get('solved')
        result['human_verification_blocking'] = state.get('blocking')
        result['human_verification_verify_button_disabled'] = state.get('verify_button_disabled')
        result['human_verification_iframe_count'] = state.get('iframe_count')

    try:
        title = (await page.title()).lower()
    except Exception:
        title = ''

    if 'just a moment' in title or 'challenge' in page.url.lower():
        result['cloudflare_challenge'] = True

    return result


async def attempt_linuxdo_human_verification(page, account_name: str, timeout_ms: int = 25000) -> bool:
    """尝试自动触发并等待 LinuxDo Human Verification 完成

    说明：
    - 不引入第三方打码服务
    - 只做轻量自动尝试：点击 Verify / hCaptcha checkbox，并等待 token
    - 若环境可信且站点允许，有机会自动通过；否则走明确降级
    """
    result = await try_bypass_linuxdo_human_verification(page, account_name, timeout=timeout_ms)
    return bool(result.get('solved'))
