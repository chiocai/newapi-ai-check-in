# 如何添加标准 New-API 站点

本文档说明如何将支持 LinuxDo OAuth 的标准 New-API 站点添加到自动签到项目中。

## 前置条件

站点必须满足以下条件才能添加：

✅ **必须支持 LinuxDo OAuth 登录**（或 GitHub OAuth）
✅ 使用标准 New-API 接口结构
✅ 支持 `/api/user/checkin` 或类似的签到接口

## 添加步骤

### 1. 检查站点是否支持 LinuxDo OAuth

访问站点的 **`/console/personal`** 页面（如 `https://example.com/console/personal`），系统会自动跳转到登录页面，此时查看是否有 **"使用 LinuxDO 继续"** 按钮。

**重要提示**：某些站点的登录页面（`/login`）默认不显示 LinuxDo 登录按钮，需要先访问 `/console/personal` 触发跳转后才会显示。

**示例**：
- ✅ `hotaruapi.com/console/personal` → 跳转到登录页，显示 LinuxDo 按钮
- ✅ `newapi.linuxdo.edu.rs/console/personal` → 跳转到登录页，显示 LinuxDo 按钮
- ✅ `api.feisakura.fun/console/personal` → 跳转到登录页，显示 LinuxDo 按钮
- ❌ 某些站点仅支持邮箱登录，无 LinuxDo 选项

### 2. 获取 LinuxDo OAuth Client ID

#### 方法一：通过浏览器开发者工具

1. 访问站点的 `/console/personal` 页面（会自动跳转到登录页）
2. 打开浏览器开发者工具（F12）
3. 切换到 **Network（网络）** 标签
4. 点击 **"使用 LinuxDO 继续"** 按钮
5. 查看跳转的 URL，格式如下：
   ```
   https://connect.linux.do/oauth2/authorize?response_type=code&client_id=XXXXXX&state=YYYY
   ```
6. 复制 `client_id=` 后面的值

#### 方法二：使用 Claude Code 自动获取

```bash
# 使用 Playwright 自动获取
uv run python3 -c "
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()
    page.goto('https://example.com/login')

    # 等待并点击 LinuxDo 登录按钮
    page.wait_for_selector('text=使用 LinuxDO 继续')

    # 监听新标签页
    with page.expect_popup() as popup_info:
        page.click('text=使用 LinuxDO 继续')

    new_page = popup_info.value
    url = new_page.url
    print(f'OAuth URL: {url}')

    # 提取 client_id
    import re
    match = re.search(r'client_id=([^&]+)', url)
    if match:
        print(f'Client ID: {match.group(1)}')

    browser.close()
"
```

### 3. 检查站点是否需要 WAF Cookies 绕过

访问站点，查看是否有 Cloudflare 或其他 WAF 防护页面。

- 如果有 Cloudflare 验证页面 → 设置 `bypass_method="waf_cookies"`
- 如果直接可访问 → 设置 `bypass_method=None`

### 4. 添加站点配置到 `utils/config.py`

在 `_load_providers` 方法的 `providers` 字典中添加新站点配置：

```python
"站点名称": ProviderConfig(
    name="站点名称",
    origin="https://站点域名",
    login_path="/login",
    status_path="/api/status",
    auth_state_path="/api/oauth/state",
    sign_in_path=None,  # 签到通过 New-API 通用签到完成（账号配置 checkin: true）
    user_info_path="/api/user/self",
    topup_path=None,
    get_cdk=None,
    api_user_key="new-api-user",
    github_client_id=None,  # 如果支持 GitHub OAuth，填写 client_id
    github_auth_path=None,
    linuxdo_client_id="从步骤2获取的client_id",
    linuxdo_auth_path="/api/oauth/linuxdo",
    aliyun_captcha=False,
    bypass_method=None,  # 或 "waf_cookies"
),
```

#### 配置说明

| 参数 | 说明 | 常见值 |
|------|------|--------|
| `name` | 站点标识符（唯一） | 小写字母+数字 |
| `origin` | 站点域名（含 https://） | `https://example.com` |
| `login_path` | 登录页面路径 | `/login` |
| `status_path` | 状态 API 路径 | `/api/status` |
| `auth_state_path` | OAuth 状态 API | `/api/oauth/state` |
| `sign_in_path` | 签到 API 路径 | `None`（通用签到）或 `/api/user/checkin` |
| `user_info_path` | 用户信息 API | `/api/user/self` |
| `topup_path` | 充值 API | `None` 或 `/api/user/topup` |
| `get_cdk` | CDK 获取函数 | `None`（无需 CDK） |
| `api_user_key` | Cookie 中的用户标识 | `new-api-user` |
| `github_client_id` | GitHub OAuth ID | `None` 或具体 ID |
| `linuxdo_client_id` | LinuxDo OAuth ID | **必填**（从步骤2获取） |
| `linuxdo_auth_path` | LinuxDo OAuth 路径 | `/api/oauth/linuxdo` |
| `aliyun_captcha` | 是否有阿里云验证码 | `False` |
| `bypass_method` | WAF 绕过方式 | `None` 或 `"waf_cookies"` |

### 5. 配置示例

#### 示例 1：标准站点（无 WAF）

```python
"feisakura": ProviderConfig(
    name="feisakura",
    origin="https://api.feisakura.fun",
    login_path="/login",
    status_path="/api/status",
    auth_state_path="/api/oauth/state",
    sign_in_path=None,
    user_info_path="/api/user/self",
    topup_path=None,
    get_cdk=None,
    api_user_key="new-api-user",
    github_client_id=None,
    github_auth_path=None,
    linuxdo_client_id="XPXmWksr3NcH2aiz0MgqK5jtEmfdfZ0Q",
    linuxdo_auth_path="/api/oauth/linuxdo",
    aliyun_captcha=False,
    bypass_method=None,
),
```

#### 示例 2：需要 WAF 绕过的站点

```python
"anyrouter": ProviderConfig(
    name="anyrouter",
    origin="https://anyrouter.top",
    login_path="/login",
    status_path="/api/status",
    auth_state_path="/api/oauth/state",
    sign_in_path="/api/user/sign_in",
    user_info_path="/api/user/self",
    topup_path="/api/user/topup",
    api_user_key="new-api-user",
    github_client_id="Ov23liOwlnIiYoF3bUqw",
    github_auth_path="/api/oauth/github",
    linuxdo_client_id="8w2uZtoWH9AUXrZr1qeCEEmvXLafea3c",
    linuxdo_auth_path="/api/oauth/linuxdo",
    aliyun_captcha=False,
    bypass_method="waf_cookies",  # 需要浏览器绕过 Cloudflare
),
```

### 6. 测试配置

创建测试脚本验证配置是否正确：

```python
#!/usr/bin/env python3
import asyncio
import os

os.environ.pop("ACCOUNTS", None)

from utils.config import AppConfig, AccountConfig
from utils.linuxdo_session import LinuxDoSessionManager
from checkin import CheckIn


async def test_site():
    account_data = {
        "name": "test-account",
        "provider": "站点名称",  # 修改为你的站点名称
        "checkin": True,
        "linux.do": {
            "username": "你的用户名",
            "password": "你的密码"
        }
    }

    account_config = AccountConfig.from_dict(account_data, 0)
    providers = AppConfig._load_providers("PROVIDERS")
    provider_config = providers.get("站点名称")  # 修改为你的站点名称

    if not provider_config:
        print("❌ Provider 配置未找到")
        return

    print(f"✅ Provider 配置加载成功:")
    print(f"   - origin: {provider_config.origin}")
    print(f"   - linuxdo_client_id: {provider_config.linuxdo_client_id}")

    # 预登录 Linux.do
    linuxdo_config = account_config.linux_do
    username = linuxdo_config.get("username")
    password = linuxdo_config.get("password")

    session = await LinuxDoSessionManager.get_session(username, password)
    linuxdo_session = LinuxDoSessionManager.get_cached_session(username)

    # 执行签到
    checkin = CheckIn(
        "test-account",
        account_config,
        provider_config,
        global_proxy=None,
        linuxdo_session=linuxdo_session,
    )

    results = await checkin.execute()
    print("\n📋 签到结果:")
    for result in results:
        print(f"   {result}")


if __name__ == "__main__":
    asyncio.run(test_site())
```

运行测试：

```bash
uv run python3 test_site.py
```

### 7. 使用配置

在 `.env` 文件或环境变量中添加账号配置：

```json
[
  {
    "name": "我的账号",
    "provider": "站点名称",
    "checkin": true,
    "linux.do": {
      "username": "你的LinuxDo用户名",
      "password": "你的LinuxDo密码"
    }
  }
]
```

### 8. 提交代码

```bash
git add utils/config.py
git commit -m "feat: 新增 站点名称 站点签到支持

- 添加 站点域名 站点配置
- 使用 LinuxDo OAuth 认证 (client_id: XXXXX)
- 支持 New-API 通用签到功能

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"

git push
```

## 常见问题

### Q1: 站点没有 LinuxDo 登录按钮怎么办？

**A**: 该站点不支持自动签到。本项目依赖 OAuth 登录实现自动化，纯邮箱/密码登录的站点无法添加。

### Q2: 如何判断是否需要 `bypass_method="waf_cookies"`？

**A**: 访问站点时如果看到 Cloudflare 验证页面（"Checking your browser"），则需要设置。

### Q3: `sign_in_path` 应该设置为什么？

**A**:
- 如果站点支持 New-API 通用签到（查询用户信息时自动签到），设置为 `None`
- 如果需要手动调用签到接口，设置为 `/api/user/checkin` 或站点的签到路径

### Q4: 如何验证 client_id 是否正确？

**A**: 在浏览器中访问：
```
https://connect.linux.do/oauth2/authorize?response_type=code&client_id=你的client_id&state=test
```
如果跳转到授权页面，说明 client_id 正确。

## 已支持的站点列表

| 站点名称 | 域名 | Provider 名称 | LinuxDo OAuth | WAF 绕过 |
|---------|------|--------------|--------------|---------|
| anyrouter | anyrouter.top | anyrouter | ✅ | ✅ |
| hotaruapi | hotaruapi.com | hotaruapi | ✅ | ❌ |
| kfcapi | kfc-api.sxxe.net | kfcapi | ✅ | ❌ |
| feisakura | api.feisakura.fun | feisakura | ✅ | ❌ |
| wong | wzw.pp.ua | wong | ✅ | ❌ |
| codex661118 | codex.661118.xyz | codex661118 | ✅ | ❌ |
| gyapi | gyapi.zxiaoruan.cn | gyapi | ✅ | ✅ |
| huan666 | ai.huan666.de | huan666 | ✅ | ❌ |
| 慕鸢の公益站 | newapi.linuxdo.edu.rs | linuxdoedu | ✅ | ❌ |
| Einzieg API | api.einzieg.site | einzieg | ✅ | ❌ |
| Jarvis API | ai.ctacy.cc | jarvisapi | ✅ | ❌ |
| Lemon API | justdoitme.me | lemonapi | ✅ | ❌ |
| AIPM | emtf.aipm9527.online | aipm | ✅ | ❌ |
| NPCodex | npcodex.kiroxubei.tech | npcodex | ✅ | ❌ |
| 361888 API | api.361888.xyz | api361888 | ✅ | ❌ |

## 参考资料

- [New-API 项目](https://github.com/QuantumNous/new-api)
- [LinuxDo OAuth 文档](https://connect.linux.do/docs)
- [项目 README](../README.md)
