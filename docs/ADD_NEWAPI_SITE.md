# 如何添加 NewAPI 站点

现在普通 NewAPI 站点统一维护在仓库根目录的 `newapi-sites.txt`，**不需要再改 `utils/config.py`**。

## 1. 确认站点模式

先确认站点属于哪一类：

- `newapi`：标准 New-API 通用签到
- `auto`：登录完成后站点自动签到，无需额外请求签到接口
- `manual:/path`：非标准签到接口，例如 `manual:/api/user/checkin`
- `newapi-waf` / `manual-waf:/path` / `auto-waf`：需要先用无头浏览器过 Cloudflare / WAF
- `turnstile:<site_key>`：需要 Turnstile 验证

## 2. 获取 LinuxDo Client ID

点击站点登录页里的“使用 LinuxDO 继续”，新窗口地址里会带：

```text
https://connect.linux.do/oauth2/authorize?...&client_id=XXXXXX&state=...
```

把 `client_id` 记下来，追加到该站点行里：

```txt
linuxdo_client_id=XXXXXX
```

如果不填，脚本会优先尝试自动探测。
自动探测结果默认写入 `storage-states/newapi-sites.runtime.json`，不会直接改 `newapi-sites.txt`。

## 3. 编辑 `newapi-sites.txt`

一行一个站点，格式如下：

```txt
name | origin | mode | 可选 key=value
```

字段说明：

- **必配**
  - `name`：站点唯一标识
  - `origin`：站点根地址
  - `mode`：站点签到模式
- **通常可自动发现**
  - `linuxdo_client_id`
  - `github_client_id`
  - `turnstile_site_key`
- **建议手工填写以提高首次成功率**
  - `linuxdo_client_id`
  - `turnstile:<site_key>` 里的 `site_key`
- **仅特殊站点通常需要手工写**
  - `api_user_key`
  - `login_path`
  - `console_personal_path`
  - `status_path`
  - `auth_state_path`
  - `user_info_path`
  - `topup_path`
  - `linuxdo_auth_path`
  - `github_auth_path`
  - `aliyun_captcha=true`

示例：

```txt
agentrouter | https://agentrouter.org | newapi
anyrouter | https://anyrouter.top | manual-waf:/api/user/sign_in | linuxdo_client_id=...
wong | https://wzw.pp.ua | manual:/api/user/checkin
linuxdoedu | https://newapi.linuxdo.edu.rs | newapi-waf
lemonapi | https://justdoitme.me | turnstile
```

常用可选字段：

- `linuxdo_client_id=...`
- `github_client_id=...`
- `turnstile_site_key=...`
- `aliyun_captcha=true`
- `api_user_key=...`
- `login_path=...`
- `console_personal_path=...`
- `status_path=...`
- `auth_state_path=...`
- `user_info_path=...`
- `topup_path=...`
- `linuxdo_auth_path=...`
- `github_auth_path=...`

特殊说明：

- `anyrouter` 当前建议继续按旧逻辑配置为 `manual-waf:/api/user/sign_in`
- 原因是该站点对 WAF / 登录态更敏感，直接沿用历史稳定配置更稳

## 4. 本地验证

```bash
uv run pytest tests/test_site_config.py tests/test_main_notifications.py
uv run python -u main.py
```

如果只想测试某几个站点，可临时复制一个精简版 `sites.txt`，再通过：

```bash
NEWAPI_SITES_FILE=/path/to/tmp-sites.txt uv run python -u main.py
```
