# newapi.ai 多账号自动签到

用于公益站多账号每日签到。  

Affs:
- [AnyRouter](https://anyrouter.top/register?aff=Ar33)

其它使用 `newapi.ai` 功能相似, 可自定义 `provider` 支持。

## 功能特性

- ✅ 单个/多账号自动签到
- ✅ 多种机器人通知（可选）
- ✅ linux.do 登录认证
- ✅ github 登录认证 (with OTP)
- ✅ Cloudflare bypass

## 使用方法

### 1. Fork 本仓库

点击右上角的 "Fork" 按钮，将本仓库 fork 到你的账户。

### 2. 设置 GitHub Environment Secret

1. 在你 fork 的仓库中，点击 "Settings" 选项卡
2. 在左侧菜单中找到 "Environments" -> "New environment"
3. 新建一个名为 `production` 的环境
4. 点击新建的 `production` 环境进入环境配置页
5. 点击 "Add environment secret" 创建 secret：
   - Name: `ACCOUNTS`
   - Value: 你的多账号配置数据

### 3. 多账号配置格式
> 如果未提供 `name` 字段，会使用 `Account 1`、`Account 2` 等默认名称。  
> 配置中 `cookies`、`github`、`linux.do` 必须至少配置 1 个。   
> 使用 `cookies` 设置时，`api_user` 字段必填。

#### 最常用配置：只配全局 `linux.do`

如果你只跑 `newapi-sites.txt` 里的普通 NewAPI 站点，**通常只需要配置全局 `linux.do` 账号列表**：

```json
{
  "linux.do": [
    {
      "username": "myuser",
      "password": "mypass"
    },
    {
      "username": "user2",
      "password": "pass2"
    }
  ]
}
```

脚本会自动把这些 LinuxDo 账号展开到 `newapi-sites.txt` 里的普通站点。

#### 什么时候还需要 `accounts`

只有下面这些情况，才通常需要额外写 `accounts`：

- 你要启用 **特殊 provider**，例如 `special:x666`、`special:b4u`、`special:fuli_wheel`
- 某个账号需要 **额外字段**，例如 `x666` 的 `access_token`
- 某个账号要用 **单独代理**
- 某个账号要用 **cookies / github** 登录，而不是全局 `linux.do`
- 你只想启用少数特殊站点，不想跟随 `newapi-sites.txt` 自动展开

像 `x666` 这种特殊站点，建议继续放在 `ACCOUNTS.accounts` 中单独控制，不再放进 `newapi-sites.txt`。

如果你还希望在 `token` 失效后，自动回退到 LinuxDo 浏览器登录刷新 token，也应该继续用下面这种 `accounts` 写法：

示例：给 `x666` 单独配置额外参数

```json
{
  "linux.do": [
    {
      "username": "myuser",
      "password": "mypass"
    }
  ],
  "accounts": [
    {
      "provider": "x666",
      "linux.do": {
        "username": "special_user",
        "password": "special_pass"
      },
      "access_token": "provider: x666 推荐配置"
    }
  ]
}
```

如果你有 **两个 `x666` 账号 / token**，就继续在 `accounts` 里写两条：

```json
{
  "linux.do": [
    {
      "username": "myuser",
      "password": "mypass"
    }
  ],
  "accounts": [
    {
      "name": "x666-1",
      "provider": "x666",
      "linux.do": {
        "username": "special_user_1",
        "password": "special_pass_1"
      },
      "access_token": "第一个x666_access_token"
    },
    {
      "name": "x666-2",
      "provider": "x666",
      "linux.do": {
        "username": "special_user_2",
        "password": "special_pass_2"
      },
      "access_token": "第二个x666_access_token"
    }
  ]
}
```

说明：

- `accounts` 里每一条 `x666` 都会作为一个独立账号运行
- `name` 建议显式填写，方便通知里区分两个 `x666` 账号
- 如果某条 `access_token` 失效，该条账号仍可尝试用它自己的 `linux.do` 配置回退登录刷新

#### 字段说明：

- `name` (可选)：自定义账号显示名称，用于通知和日志中标识账号
- `provider` (可选)：特殊站点或独立 provider；普通 NewAPI 站点建议改 `newapi-sites.txt`
- `proxy` (可选)：单个账号代理配置，支持 `http`、`socks5` 代理
- `cookies`(可选)：用于身份验证的 cookies 数据
- `api_user`(cookies 设置时必需)：用于请求头的 new-api-user 参数
- `linux.do`(可选)：用于登录身份验证
  - `username`: 用户名
  - `password`: 密码
- `github`(可选)：用于登录身份验证
  - `username`: 用户名
  - `password`: 密码

#### NewAPI 站点配置（推荐）

普通 NewAPI 站点不再需要写进 `ACCOUNTS` 或 `PROVIDERS`，直接维护仓库根目录的 `newapi-sites.txt`：

```txt
agentrouter | https://agentrouter.org | newapi
anyrouter | https://anyrouter.top | manual-waf:/api/user/sign_in | linuxdo_client_id=...
wong | https://wzw.pp.ua | manual:/api/user/checkin
linuxdoedu | https://newapi.linuxdo.edu.rs | newapi-waf
lemonapi | https://justdoitme.me | turnstile
```

- `newapi`：标准 New-API 通用签到
- `auto`：登录后自动签到，无需额外请求签到接口
- `manual:/path`：非标准签到接口
- `newapi-waf` / `manual-waf:/path` / `auto-waf`：需要无头浏览器先过 CF / WAF
- `turnstile:<site_key>`：需要 Turnstile
- `anyrouter` 当前建议继续按旧逻辑配置为 `manual-waf:/api/user/sign_in`，不要改成 `auto-waf`
- 可选 `linuxdo_client_id=...`、`github_client_id=...`、`turnstile_site_key=...`；不写时脚本会尝试自动获取
- 自动发现到的 `linuxdo_client_id`、`turnstile_site_key` 等会写入 `storage-states/newapi-sites.runtime.json`
- `newapi-sites.txt` 中：
  - **必配**：`name | origin | mode`
  - **通常可自动发现**：`linuxdo_client_id`、`github_client_id`、`turnstile_site_key`
  - **特殊站点才常需手工写**：`api_user_key`、`login_path`、`console_personal_path`、`status_path`、`auth_state_path`、`user_info_path`、`topup_path`

`PROVIDERS` 环境变量仍可用于临时覆盖或追加特殊 provider，但日常新增/删除站点建议只改 `newapi-sites.txt`。


#### 代理配置
> 应用到所有的账号，如果单个账号需要使用代理，请在单个账号配置中添加 `proxy` 字段。  
> 打开 [webshare](https://dashboard.webshare.io/) 注册账号，获取免费代理

在仓库的 Settings -> Environments -> production -> Environment secrets 中添加：
   - Name: `PROXY`
   - Value: 代理服务器地址


```bash
{
  "server": "http://username:password@proxy.example.com:8080"
}

或者

{
  "server": "http://proxy.example.com:8080",
  "username": "username",
  "password": "password"
}
```

#### 可选：把 LinuxDo 预热态放进 `ACCOUNTS` 配置

如果你的 GitHub workflow 已经会注入 `ACCOUNTS`，最省事的方式是把本地预热好的
`LinuxDo storage state` 放到 `ACCOUNTS` 顶层字段 `linuxdo_storage_states` 中。

本地导出可直接粘贴的 payload：

```bash
uv run python export_storage_states_secret.py
```

然后把输出内容放进 `ACCOUNTS` 顶层，例如：

```json
{
  "linux.do": [
    {
      "username": "your-linuxdo-user",
      "password": "your-linuxdo-pass"
    }
  ],
  "linuxdo_storage_states": {
    "linuxdo_9e845f04_storage_state.json": {
      "cookies": [],
      "origins": []
    },
    "linuxdo_a0598ad1_storage_state.json": {
      "cookies": [],
      "origins": []
    }
  },
  "accounts": []
}
```

运行时会自动把这些文件恢复到 `storage-states/`，无需提交到仓库。

#### 可选：单独放进 GitHub Secrets

如果你已经在本地完成过 `LinuxDo` 可见浏览器预热，不要把 `storage-states/*.json` 直接提交进仓库。  
更安全的做法是把它们放进 GitHub `Environment secrets`：

- `PREWARMED_STORAGE_STATES`
- 或 `PREWARMED_STORAGE_STATES_B64`

本地导出 Secret 内容：

```bash
uv run python export_storage_states_secret.py
```

如果还想一起带上运行时站点自动发现结果：

```bash
uv run python export_storage_states_secret.py --include-runtime
```

将输出内容复制到 GitHub `Settings -> Environments -> production -> Environment secrets` 中的
`PREWARMED_STORAGE_STATES` 即可。

说明：

- 更推荐直接放进 `ACCOUNTS.linuxdo_storage_states`
- 只建议放 `linuxdo_*_storage_state.json`
- 这些内容本质上仍是敏感登录态，请只存到 `Secrets`，不要提交到仓库
- 首次成功运行后，GitHub Actions 还会继续用缓存机制保留并更新这些文件


#### 如何获取 cookies 与 api_user 的值。

通过 F12 工具，切到 Application 面板，Cookies -> session 的值，最好重新登录下，但有可能提前失效，失效后报 401 错误，到时请再重新获取。

![获取 cookies](./assets/request-cookie-session.png)

通过 F12 工具，切到 Application 面板，面板，Local storage -> user 对象中的 id 字段。

![获取 api_user](./assets/request-api-user.png)

#### `GitHub` 在新设备上登录会有两次验证

通过打印日志中链接打开并输入验证码。

![输入 OTP](./assets/github-otp.png)

### 4. 启用 GitHub Actions

1. 在你的仓库中，点击 "Actions" 选项卡
2. 如果提示启用 Actions，请点击启用
3. 找到 "newapi.ai 自动签到" workflow
4. 点击 "Enable workflow"

### 5. 测试运行

你可以手动触发一次签到来测试：

1. 在 "Actions" 选项卡中，点击 "newapi.ai 自动签到"
2. 点击 "Run workflow" 按钮
3. 确认运行

![运行结果](./assets/check-in.png)

## 执行时间

- 脚本每 8 小时执行一次（1. action 无法准确触发，基本延时 1~1.5h；2. 目前观测到 anyrouter.top 的签到是每 24h 而不是零点就可签到）
- 你也可以随时手动触发签到

## 注意事项

- 可以在 Actions 页面查看详细的运行日志
- 支持部分账号失败，只要有账号成功签到，整个任务就不会失败
- `GitHub` 新设备 OTP 验证，注意日志中的链接或配置了通知注意接收的链接，访问链接进行输入验证码

## 开启通知

脚本支持多种通知方式，可以通过配置以下环境变量开启，如果 `webhook` 有要求安全设置，例如钉钉，可以在新建机器人时选择自定义关键词，填写 `newapi.ai`。

### 邮箱通知

- `EMAIL_USER`: 发件人邮箱地址
- `EMAIL_PASS`: 发件人邮箱密码/授权码
- `CUSTOM_SMTP_SERVER`: 自定义发件人 SMTP 服务器(可选)
- `EMAIL_TO`: 收件人邮箱地址

### 钉钉机器人

- `DINGDING_WEBHOOK`: 钉钉机器人的 Webhook 地址

### 飞书机器人

- `FEISHU_WEBHOOK`: 飞书机器人的 Webhook 地址

### 企业微信机器人

- `WEIXIN_WEBHOOK`: 企业微信机器人的 Webhook 地址

### PushPlus 推送

- `PUSHPLUS_TOKEN`: PushPlus 的 Token

### Server 酱

- `SERVERPUSHKEY`: Server 酱的 SendKey

配置步骤：

1. 在仓库的 Settings -> Environments -> production -> Environment secrets 中添加上述环境变量
2. 每个通知方式都是独立的，可以只配置你需要的推送方式
3. 如果某个通知方式配置不正确或未配置，脚本会自动跳过该通知方式

## 故障排除

如果签到失败，请检查：

1. 账号配置格式是否正确
2. 网站是否更改了签到接口
3. 查看 Actions 运行日志获取详细错误信息

## 本地开发环境设置

如果你需要在本地测试或开发，请按照以下步骤设置：

```bash
# 安装所有依赖
uv sync --dev

# 安装 Camoufox 浏览器
python3 -m camoufox fetch

# 按 .env.example 创建 .env
uv run main.py
```

## 手工预热 LinuxDo 会话

如果某些站点登录时被 `LinuxDo` 的 `Human Verification / hCaptcha` 拦截，可以先手工预热会话，再让签到脚本复用缓存：

```bash
uv run python prepare_linuxdo_session.py
```

只预热某一个 LinuxDo 账号：

```bash
uv run python prepare_linuxdo_session.py --username your_linuxdo_username
```

说明：

- 脚本会打开可见浏览器
- 会自动预填账号密码
- 你只需要在浏览器里手工完成登录 / 验证
- 成功后会保存到 `storage-states/linuxdo_<hash>_storage_state.json`
- 后续普通签到流程会优先复用这份会话缓存

## 测试

```bash
uv sync --dev

# 安装 Camoufox 浏览器
python3 -m camoufox fetch

# 运行测试
uv run pytest tests/
```

## 免责声明

本脚本仅用于学习和研究目的，使用前请确保遵守相关网站的使用条款.
