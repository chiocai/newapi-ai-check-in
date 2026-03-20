#!/usr/bin/env python3
"""
配置管理模块
"""

import inspect
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncGenerator, Callable, Dict, List, Literal

from utils.get_cdk import (
	get_fuli_wheel_cdk,
	get_x666_cdk,
)
from utils.signature import aiai_li_sign_in_url

# 前向声明 AccountConfig 类型，用于类型注解
# 定义 CDK 获取函数的类型：接收 AccountConfig 参数，返回 str | List[str] | None
CdkGetterFunc = Callable[["AccountConfig"], str | List[str] | None]

DEFAULT_NEWAPI_SITES_FILE = 'newapi-sites.txt'
NEWAPI_SITES_FILE_ENV = 'NEWAPI_SITES_FILE'
DEFAULT_NEWAPI_SITES_RUNTIME_FILE = 'storage-states/newapi-sites.runtime.json'
NEWAPI_SITES_RUNTIME_FILE_ENV = 'NEWAPI_SITES_RUNTIME_FILE'


@dataclass
class ProviderConfig:
	"""Provider 配置"""

	name: str
	origin: str
	login_path: str = '/login'
	console_personal_path: str = '/console/personal'
	status_path: str | None = '/api/status'
	auth_state_path: str | None = '/api/oauth/state'
	sign_in_path: str | Callable[[str, str | int], str] | None = '/api/user/sign_in'
	user_info_path: str | None = '/api/user/self'
	topup_path: str | None = '/api/user/topup'
	get_cdk: CdkGetterFunc | List[CdkGetterFunc] | None = None
	api_user_key: str = 'new-api-user'
	github_client_id: str | None = None
	github_auth_path: str | None = '/api/oauth/github'
	linuxdo_client_id: str | None = None
	linuxdo_auth_path: str | None = '/api/oauth/linuxdo'
	aliyun_captcha: bool = False
	bypass_method: Literal['waf_cookies'] | None = None
	turnstile_site_key: str | None = None

	@classmethod
	def from_dict(cls, name: str, data: dict) -> 'ProviderConfig':
		"""从字典创建 ProviderConfig"""
		return cls(
			name=name,
			origin=data['origin'],
			login_path=data.get('login_path', '/login'),
			console_personal_path=data.get('console_personal_path', '/console/personal'),
			status_path=data.get('status_path', '/api/status'),
			auth_state_path=data.get('auth_state_path', '/api/oauth/state'),
			sign_in_path=data.get('sign_in_path', '/api/user/sign_in'),
			user_info_path=data.get('user_info_path', '/api/user/self'),
			topup_path=data.get('topup_path', '/api/user/topup'),
			get_cdk=data.get('get_cdk'),
			api_user_key=data.get('api_user_key', 'new-api-user'),
			github_client_id=data.get('github_client_id'),
			github_auth_path=data.get('github_auth_path', '/api/oauth/github'),
			linuxdo_client_id=data.get('linuxdo_client_id'),
			linuxdo_auth_path=data.get('linuxdo_auth_path', '/api/oauth/linuxdo'),
			aliyun_captcha=data.get('aliyun_captcha', False),
			bypass_method=data.get('bypass_method'),
			turnstile_site_key=data.get('turnstile_site_key'),
		)

	def needs_waf_cookies(self) -> bool:
		"""判断是否需要获取 WAF cookies"""
		return self.bypass_method == 'waf_cookies'

	def needs_manual_check_in(self) -> bool:
		"""判断是否需要手动调用签到接口"""
		return self.sign_in_path is not None

	def needs_manual_topup(self) -> bool:
		"""判断是否需要手动执行充值（通过 CDK）"""
		return self.topup_path is not None and self.get_cdk is not None

	def get_login_url(self) -> str:
		"""获取登录 URL"""
		return f'{self.origin}{self.login_path}'

	def get_status_url(self) -> str:
		"""获取状态 URL"""
		return f'{self.origin}{self.status_path}'

	def get_console_personal_url(self) -> str:
		"""获取 console/personal URL"""
		return f'{self.origin}{self.console_personal_path}'

	def get_auth_state_url(self) -> str:
		"""获取认证状态 URL"""
		return f'{self.origin}{self.auth_state_path}'

	def get_sign_in_url(self, user_id: str | int) -> str | None:
		"""获取签到 URL"""
		if not self.sign_in_path:
			return None

		if callable(self.sign_in_path):
			return self.sign_in_path(self.origin, user_id)

		return f'{self.origin}{self.sign_in_path}'

	def get_user_info_url(self) -> str:
		"""获取用户信息 URL"""
		return f'{self.origin}{self.user_info_path}'

	def get_topup_url(self) -> str | None:
		"""获取充值 URL"""
		if not self.topup_path:
			return None
		return f'{self.origin}{self.topup_path}'

	def get_github_auth_url(self) -> str:
		"""获取 GitHub 认证 URL"""
		return f'{self.origin}{self.github_auth_path}'

	def get_linuxdo_auth_url(self) -> str:
		"""获取 LinuxDo 认证 URL"""
		return f'{self.origin}{self.linuxdo_auth_path}'

	def to_dict(self) -> dict:
		"""转为可复用字典"""
		return {
			'origin': self.origin,
			'login_path': self.login_path,
			'console_personal_path': self.console_personal_path,
			'status_path': self.status_path,
			'auth_state_path': self.auth_state_path,
			'sign_in_path': self.sign_in_path,
			'user_info_path': self.user_info_path,
			'topup_path': self.topup_path,
			'get_cdk': self.get_cdk,
			'api_user_key': self.api_user_key,
			'github_client_id': self.github_client_id,
			'github_auth_path': self.github_auth_path,
			'linuxdo_client_id': self.linuxdo_client_id,
			'linuxdo_auth_path': self.linuxdo_auth_path,
			'aliyun_captcha': self.aliyun_captcha,
			'bypass_method': self.bypass_method,
			'turnstile_site_key': self.turnstile_site_key,
		}

	def apply_overrides(self, overrides: dict) -> 'ProviderConfig':
		"""应用运行时覆盖配置"""
		data = self.to_dict()
		for key, value in overrides.items():
			if key.startswith('_'):
				continue
			data[key] = value
		return ProviderConfig.from_dict(self.name, data)

	async def iter_get_cdk(self, account_config: 'AccountConfig') -> AsyncGenerator[tuple, None]:
		"""迭代获取 CDK（异步生成器方式）"""
		if not self.get_cdk:
			return

		async def call_func(func):
			if inspect.iscoroutinefunction(func):
				return await func(account_config)
			return func(account_config)

		funcs = self.get_cdk if isinstance(self.get_cdk, list) else [self.get_cdk]
		for func in funcs:
			if not callable(func):
				continue

			result = await call_func(func)
			if not result:
				continue

			if isinstance(result, dict) and 'cdks' in result:
				cdks = result.get('cdks', [])
				if cdks:
					yield (cdks, result)
				else:
					yield ([], result)
			elif isinstance(result, dict):
				yield ([], result)
			elif isinstance(result, list):
				yield (result, result)
			else:
				yield ([result], result)


@dataclass
class SiteDefinition:
	"""站点配置定义"""

	name: str
	provider: ProviderConfig
	checkin: bool = False
	mode: str = 'manual'
	account_defaults: dict = field(default_factory=dict)


@dataclass
class AccountConfig:
	"""账号配置"""

	provider: str = 'anyrouter'
	cookies: dict | str = ''
	api_user: str = ''
	name: str | None = None
	linux_do: dict | None = None
	github: dict | None = None
	proxy: dict | None = None
	checkin: bool = False
	extra: dict = field(default_factory=dict)

	@classmethod
	def from_dict(cls, data: dict, index: int) -> 'AccountConfig':
		"""从字典创建 AccountConfig"""
		provider = data.get('provider', 'anyrouter')
		name = data.get('name', f'Account {index + 1}')
		cookies = data.get('cookies', '')
		linux_do = data.get('linux.do')
		github = data.get('github')
		proxy = data.get('proxy')
		checkin = data.get('checkin', False)

		known_keys = {'provider', 'name', 'cookies', 'api_user', 'linux.do', 'github', 'proxy', 'checkin'}
		extra = {k: v for k, v in data.items() if k not in known_keys}

		return cls(
			provider=provider,
			name=name if name else None,
			cookies=cookies,
			api_user=data.get('api_user', ''),
			linux_do=linux_do,
			github=github,
			proxy=proxy,
			checkin=checkin,
			extra=extra,
		)

	def get_display_name(self, index: int = 0) -> str:
		"""获取显示名称"""
		return self.name if self.name else f'Account {index + 1}'

	def get(self, key: str, default=None):
		"""获取配置值，优先从已知属性获取，否则从 extra 中获取"""
		if hasattr(self, key) and key != 'extra':
			value = getattr(self, key)
			return value if value is not None else default
		return self.extra.get(key, default)


@dataclass
class AppConfig:
	"""应用配置"""

	providers: Dict[str, ProviderConfig]
	accounts: List['AccountConfig'] = field(default_factory=list)
	global_proxy: Dict | None = None
	site_definitions: Dict[str, SiteDefinition] = field(default_factory=dict)
	runtime_sites_file: str = DEFAULT_NEWAPI_SITES_RUNTIME_FILE

	@classmethod
	def load_from_env(
		cls,
		providers_env: str = 'PROVIDERS',
		accounts_env: str = 'ACCOUNTS',
		proxy_env: str = 'PROXY',
		sites_file_env: str = NEWAPI_SITES_FILE_ENV,
		runtime_sites_file_env: str = NEWAPI_SITES_RUNTIME_FILE_ENV,
	) -> 'AppConfig':
		"""从环境变量加载配置"""
		site_definitions = cls._load_site_definitions(sites_file_env)
		runtime_sites_file, runtime_overrides = cls._load_runtime_site_overrides(runtime_sites_file_env)
		site_definitions = cls._merge_runtime_site_overrides(site_definitions, runtime_overrides)
		providers = cls._load_providers(providers_env, site_definitions)
		accounts = cls._load_accounts(accounts_env, site_definitions)
		global_proxy = cls._load_proxy(proxy_env)
		return cls(
			providers=providers,
			accounts=accounts,
			global_proxy=global_proxy,
			site_definitions=site_definitions,
			runtime_sites_file=str(runtime_sites_file),
		)

	@classmethod
	def _load_proxy(cls, proxy_env: str) -> Dict | None:
		"""从环境变量加载全局代理配置"""
		proxy_str = os.getenv(proxy_env)
		if not proxy_str:
			return None

		try:
			proxy = json.loads(proxy_str)
			print(f'⚙️ Global proxy loaded from {proxy_env} environment variable (dict format)')
			return proxy
		except json.JSONDecodeError:
			proxy = {'server': proxy_str}
			print(f'⚙️ Global proxy loaded from {proxy_env} environment variable: {proxy_str}')
			return proxy

	@staticmethod
	def _normalize_optional_value(value: str | None, default: str | None = None) -> str | None:
		"""规范化可选配置值"""
		if value is None:
			return default

		normalized = value.strip()
		if normalized.lower() in {'', 'none', 'null'}:
			return None

		return normalized

	@staticmethod
	def _parse_bool(value: str | None, default: bool = False) -> bool:
		"""解析布尔配置"""
		if value is None:
			return default

		return value.strip().lower() in {'1', 'true', 'yes', 'y', 'on'}

	@classmethod
	def _get_builtin_providers(cls) -> Dict[str, ProviderConfig]:
		"""返回保留在代码中的特殊 provider 配置"""
		return {
			'aiai.li': ProviderConfig(
				name='aiai.li',
				origin='https://aiai.li',
				login_path='/login',
				console_personal_path='/console/personal',
				status_path='/api/status',
				auth_state_path='/api/oauth/state',
				sign_in_path=aiai_li_sign_in_url,
				user_info_path='/api/user/self',
				topup_path='/api/user/topup',
				get_cdk=None,
				api_user_key='new-api-user',
				github_client_id=None,
				github_auth_path=None,
				linuxdo_client_id=None,
				linuxdo_auth_path='/api/oauth/linuxdo',
				aliyun_captcha=False,
				bypass_method=None,
			),
			'x666': ProviderConfig(
				name='x666',
				origin='https://x666.me',
				login_path='/login',
				console_personal_path='/console/personal',
				status_path='/api/status',
				auth_state_path='/api/oauth/state',
				sign_in_path=None,
				user_info_path='/api/user/self',
				topup_path='/api/user/topup',
				get_cdk=get_x666_cdk,
				api_user_key='new-api-user',
				github_client_id=None,
				github_auth_path=None,
				linuxdo_client_id='4OtAotK6cp4047lgPD4kPXNhWRbRdTw3',
				linuxdo_auth_path='/api/oauth/linuxdo',
				aliyun_captcha=False,
				bypass_method=None,
			),
			'fuli_wheel': ProviderConfig(
				name='fuli_wheel',
				origin='https://fuli.hxi.me',
				login_path='/login',
				console_personal_path='/console/personal',
				status_path='/api/wheel/status',
				auth_state_path=None,
				sign_in_path=None,
				user_info_path=None,
				topup_path=None,
				get_cdk=get_fuli_wheel_cdk,
				api_user_key='new-api-user',
				github_client_id=None,
				github_auth_path=None,
				linuxdo_client_id=None,
				linuxdo_auth_path=None,
				aliyun_captcha=False,
				bypass_method=None,
			),
		}

	@classmethod
	def _load_site_definitions(cls, sites_file_env: str) -> Dict[str, SiteDefinition]:
		"""从 TXT 文件加载站点配置"""
		sites_file = os.getenv(sites_file_env, DEFAULT_NEWAPI_SITES_FILE)
		sites_path = Path(sites_file).expanduser()
		if not sites_path.is_absolute():
			sites_path = Path.cwd() / sites_path

		if not sites_path.exists():
			print(f'⚠️ Sites file not found: {sites_path}, skipping TXT site loading')
			return {}

		site_definitions = {}
		for line_number, raw_line in enumerate(sites_path.read_text(encoding='utf-8').splitlines(), start=1):
			line = raw_line.split('#', 1)[0].strip()
			if not line:
				continue

			try:
				site = cls._parse_site_definition_line(line)
				site_definitions[site.name] = site
			except Exception as exc:
				print(f'⚠️ Invalid site config at {sites_path.name}:{line_number} - {exc}')

		if site_definitions:
			print(f'⚙️ Loaded {len(site_definitions)} site(s) from {sites_path}')
		else:
			print(f'⚠️ No valid site found in {sites_path}')

		return site_definitions

	@classmethod
	def _get_runtime_sites_file_path(cls, runtime_sites_file_env: str) -> Path:
		"""获取运行时站点缓存文件路径"""
		runtime_file = os.getenv(runtime_sites_file_env, DEFAULT_NEWAPI_SITES_RUNTIME_FILE)
		runtime_path = Path(runtime_file).expanduser()
		if not runtime_path.is_absolute():
			runtime_path = Path.cwd() / runtime_path
		return runtime_path

	@classmethod
	def _load_runtime_site_overrides(cls, runtime_sites_file_env: str) -> tuple[Path, dict[str, dict]]:
		"""加载运行时站点覆盖配置"""
		runtime_path = cls._get_runtime_sites_file_path(runtime_sites_file_env)
		if not runtime_path.exists():
			return runtime_path, {}

		try:
			payload = json.loads(runtime_path.read_text(encoding='utf-8'))
			if isinstance(payload, dict) and isinstance(payload.get('sites'), dict):
				return runtime_path, payload['sites']
			if isinstance(payload, dict):
				return runtime_path, payload
		except Exception as exc:
			print(f'⚠️ Failed to load runtime site overrides from {runtime_path}: {exc}')

		return runtime_path, {}

	@classmethod
	def _merge_runtime_site_overrides(
		cls,
		site_definitions: Dict[str, SiteDefinition],
		runtime_overrides: dict[str, dict],
	) -> Dict[str, SiteDefinition]:
		"""将运行时缓存覆盖到 TXT 站点配置"""
		if not runtime_overrides:
			return site_definitions

		merged = dict(site_definitions)
		for site_name, overrides in runtime_overrides.items():
			site_definition = merged.get(site_name)
			if not site_definition or not isinstance(overrides, dict):
				continue

			# 显式 `*-waf` 基线应以站点文件为准，避免旧 runtime 覆盖把站点误切回非 WAF。
			effective_overrides = dict(overrides)
			if site_definition.mode in {'newapi-waf', 'manual-waf', 'auto-waf'}:
				effective_overrides.pop('bypass_method', None)

			merged[site_name] = SiteDefinition(
				name=site_definition.name,
				provider=site_definition.provider.apply_overrides(effective_overrides),
				checkin=site_definition.checkin,
				mode=site_definition.mode,
			)

		print(f'⚙️ Applied runtime overrides for {len(runtime_overrides)} site(s)')
		return merged

	@classmethod
	def _parse_site_definition_line(cls, line: str) -> SiteDefinition:
		"""解析单行站点配置"""
		parts = [part.strip() for part in line.split('|')]
		if len(parts) < 3:
			raise ValueError('must be: name | origin | mode | optional key=value')

		name, origin, mode_token = parts[:3]
		if not name:
			raise ValueError('site name cannot be empty')
		if not origin.startswith(('http://', 'https://')):
			raise ValueError('origin must start with http:// or https://')

		options = {}
		for part in parts[3:]:
			if not part:
				continue
			if '=' not in part:
				raise ValueError(f'invalid option: {part}')
			key, value = part.split('=', 1)
			options[key.strip()] = value.strip()

		mode_name, _, mode_value = mode_token.partition(':')
		mode_name = mode_name.strip().lower()
		mode_value = mode_value.strip()
		github_client_id = cls._normalize_optional_value(options.get('github_client_id'), None)
		github_auth_path = cls._normalize_optional_value(
			options.get('github_auth_path'),
			'/api/oauth/github' if github_client_id else None,
		)

		provider_data = {
			'origin': origin,
			'login_path': options.get('login_path', '/login'),
			'console_personal_path': options.get('console_personal_path', '/console/personal'),
			'status_path': cls._normalize_optional_value(options.get('status_path'), '/api/status'),
			'auth_state_path': cls._normalize_optional_value(options.get('auth_state_path'), '/api/oauth/state'),
			'sign_in_path': '/api/user/sign_in',
			'user_info_path': cls._normalize_optional_value(options.get('user_info_path'), '/api/user/self'),
			'topup_path': cls._normalize_optional_value(options.get('topup_path'), None),
			'get_cdk': None,
			'api_user_key': options.get('api_user_key', 'new-api-user'),
			'github_client_id': github_client_id,
			'github_auth_path': github_auth_path,
			'linuxdo_client_id': cls._normalize_optional_value(options.get('linuxdo_client_id'), None),
			'linuxdo_auth_path': cls._normalize_optional_value(options.get('linuxdo_auth_path'), '/api/oauth/linuxdo'),
			'aliyun_captcha': cls._parse_bool(options.get('aliyun_captcha'), False),
			'bypass_method': cls._normalize_optional_value(options.get('bypass_method'), None),
			'turnstile_site_key': cls._normalize_optional_value(options.get('turnstile_site_key'), None),
		}

		sign_in_override = cls._normalize_optional_value(options.get('sign_in_path'), None)
		checkin = False
		account_defaults = {}

		if mode_name == 'newapi':
			provider_data['sign_in_path'] = None
			checkin = True
		elif mode_name == 'auto':
			provider_data['sign_in_path'] = None
		elif mode_name == 'newapi-waf':
			provider_data['sign_in_path'] = None
			provider_data['bypass_method'] = 'waf_cookies'
			checkin = True
		elif mode_name == 'auto-waf':
			provider_data['sign_in_path'] = None
			provider_data['bypass_method'] = 'waf_cookies'
		elif mode_name == 'manual':
			provider_data['sign_in_path'] = mode_value or sign_in_override or '/api/user/sign_in'
		elif mode_name == 'manual-waf':
			provider_data['sign_in_path'] = mode_value or sign_in_override or '/api/user/sign_in'
			provider_data['bypass_method'] = 'waf_cookies'
		elif mode_name == 'turnstile':
			provider_data['sign_in_path'] = None
			provider_data['turnstile_site_key'] = mode_value or provider_data['turnstile_site_key']
			checkin = True
		elif mode_name == 'signed':
			signer_name = (mode_value or options.get('signer', '')).strip().lower()
			if signer_name != 'aiai_li':
				raise ValueError(f'unsupported signer: {signer_name or "<empty>"}')
			provider_data['sign_in_path'] = aiai_li_sign_in_url
		elif mode_name == 'special':
			special_name = (mode_value or options.get('special', '')).strip().lower()
			if special_name == 'x666':
				provider_data['sign_in_path'] = None
				provider_data['topup_path'] = '/api/user/topup'
				provider_data['get_cdk'] = get_x666_cdk
				access_token = cls._normalize_optional_value(options.get('access_token'), None)
				if access_token:
					account_defaults['access_token'] = access_token
			elif special_name == 'fuli_wheel':
				provider_data['status_path'] = '/api/wheel/status'
				provider_data['auth_state_path'] = None
				provider_data['sign_in_path'] = None
				provider_data['user_info_path'] = None
				provider_data['topup_path'] = None
				provider_data['get_cdk'] = get_fuli_wheel_cdk
				provider_data['linuxdo_client_id'] = None
				provider_data['linuxdo_auth_path'] = None
				provider_data['github_client_id'] = None
				provider_data['github_auth_path'] = None
			else:
				raise ValueError(f'unsupported special mode: {special_name or "<empty>"}')
		else:
			raise ValueError(f'unsupported mode: {mode_name}')

		if sign_in_override is not None and mode_name not in {'manual', 'manual-waf'}:
			provider_data['sign_in_path'] = sign_in_override

		provider = ProviderConfig.from_dict(name, provider_data)
		return SiteDefinition(
			name=name,
			provider=provider,
			checkin=checkin,
			mode=mode_name,
			account_defaults=account_defaults,
		)

	@classmethod
	def _load_providers(
		cls,
		providers_env: str,
		site_definitions: Dict[str, SiteDefinition] | None = None,
	) -> Dict[str, ProviderConfig]:
		"""从环境变量和 TXT 文件加载 provider 配置"""
		providers = cls._get_builtin_providers()
		for site_name, site in (site_definitions or {}).items():
			providers[site_name] = site.provider

		providers_str = os.getenv(providers_env)
		if providers_str:
			try:
				providers_data = json.loads(providers_str)
				if not isinstance(providers_data, dict):
					print(f'⚠️ {providers_env} must be a JSON object, ignoring custom providers')
					return providers

				for name, provider_data in providers_data.items():
					try:
						providers[name] = ProviderConfig.from_dict(name, provider_data)
					except Exception as exc:
						print(f'⚠️ Failed to parse provider "{name}": {exc}, skipping')
						continue

				print(f'ℹ️ Loaded {len(providers_data)} custom provider(s) from {providers_env} environment variable')
			except json.JSONDecodeError as exc:
				print(f'⚠️ Failed to parse {providers_env} environment variable: {exc}, using default configuration only')
			except Exception as exc:
				print(f'⚠️ Error loading {providers_env}: {exc}, using default configuration only')
		else:
			print(f'❌ {providers_env} environment variable not found')

		return providers

	@classmethod
	def _apply_site_account_defaults(cls, account: dict, site_definitions: Dict[str, SiteDefinition]) -> dict:
		"""为账号应用站点默认配置"""
		if not site_definitions:
			return account

		provider_name = account.get('provider', 'anyrouter')
		site_definition = site_definitions.get(provider_name)
		if not site_definition:
			return account

		normalized = dict(account)
		normalized.setdefault('checkin', site_definition.checkin)
		for key, value in site_definition.account_defaults.items():
			normalized.setdefault(key, value)
		return normalized

	@staticmethod
	def _account_identity_key(account: dict) -> tuple:
		"""生成账号去重键"""
		provider_name = account.get('provider', 'anyrouter')

		linux_do = account.get('linux.do')
		if isinstance(linux_do, dict):
			return provider_name, 'linux.do', linux_do.get('username', '')

		github = account.get('github')
		if isinstance(github, dict):
			return provider_name, 'github', github.get('username', '')

		if account.get('cookies'):
			return provider_name, 'cookies', account.get('api_user', '')

		if account.get('access_token'):
			return provider_name, 'access_token', str(account.get('access_token'))[:24]

		return provider_name, 'unknown', account.get('name', '')

	@classmethod
	def _expand_account_with_global_linuxdo(cls, account: dict, global_linuxdo: list[dict]) -> list[dict]:
		"""用全局 linux.do 账号展开单个配置"""
		expanded_accounts = []
		for idx, linux_do in enumerate(global_linuxdo):
			new_account = dict(account)
			new_account['linux.do'] = linux_do
			if 'name' not in new_account:
				provider_name = new_account.get('provider', 'account')
				if len(global_linuxdo) > 1:
					new_account['name'] = f'{provider_name}-{idx + 1}'
				else:
					new_account['name'] = provider_name
			expanded_accounts.append(new_account)
		return expanded_accounts

	@classmethod
	def _load_accounts(
		cls,
		accounts_env: str,
		site_definitions: Dict[str, SiteDefinition] | None = None,
	) -> List['AccountConfig']:
		"""从环境变量加载多账号配置"""
		accounts_str = os.getenv(accounts_env)
		if not accounts_str:
			print(f'❌ {accounts_env} environment variable not found')
			return []

		try:
			accounts_data = json.loads(accounts_str)
			site_definitions = site_definitions or {}

			if isinstance(accounts_data, dict):
				global_linuxdo = accounts_data.get('linux.do', [])
				account_list = accounts_data.get('accounts', [])

				if global_linuxdo and not isinstance(global_linuxdo, list):
					print("❌ 'linux.do' field must be an array")
					return []
				if not isinstance(account_list, list):
					print("❌ 'accounts' field must be an array")
					return []

				expanded = []
				for account in account_list:
					if not isinstance(account, dict):
						continue

					has_auth = 'linux.do' in account or 'github' in account or 'cookies' in account
					if has_auth or not global_linuxdo:
						expanded.append(account)
					else:
						expanded.extend(cls._expand_account_with_global_linuxdo(account, global_linuxdo))

				explicit_keys = {cls._account_identity_key(account) for account in expanded}
				auto_site_count = 0
				auto_special_site_count = 0
				if site_definitions and global_linuxdo:
					for site_name, site in site_definitions.items():
						if site.mode == 'special':
							if site.account_defaults.get('access_token'):
								generated = {
									'provider': site_name,
									'name': site_name,
									**site.account_defaults,
								}
								identity_key = cls._account_identity_key(generated)
								if identity_key not in explicit_keys:
									expanded.append(generated)
									explicit_keys.add(identity_key)
									auto_special_site_count += 1
							continue

						for idx, linux_do in enumerate(global_linuxdo):
							generated = {
								'provider': site_name,
								'linux.do': linux_do,
								'checkin': site.checkin,
								'name': f'{site_name}-{idx + 1}' if len(global_linuxdo) > 1 else site_name,
							}
							identity_key = cls._account_identity_key(generated)
							if identity_key in explicit_keys:
								continue

							expanded.append(generated)
							explicit_keys.add(identity_key)
							auto_site_count += 1

				accounts_data = expanded
				print(f'⚙️ Object format detected, expanded to {len(accounts_data)} account(s)')
				if auto_site_count:
					print(
						f'⚙️ Site file detected, auto-expanded {auto_site_count} '
						f'site account(s) from {len(global_linuxdo)} Linux.do credential(s)'
					)
				if auto_special_site_count:
					print(
						f'⚙️ Auto-expanded {auto_special_site_count} special site account(s) '
						'from site defaults'
					)

			if not isinstance(accounts_data, list):
				print('❌ Account configuration must use array format [...] or object format {...}')
				return []

			accounts = []
			for i, raw_account in enumerate(accounts_data):
				if not isinstance(raw_account, dict):
					print(f'❌ Account {i + 1} configuration format is incorrect')
					return []

				account = cls._apply_site_account_defaults(raw_account, site_definitions)

				has_linux_do = 'linux.do' in account
				has_github = 'github' in account
				has_cookies = 'cookies' in account
				provider_name = account.get('provider', 'anyrouter')
				has_x666_token = provider_name == 'x666' and bool(account.get('access_token'))

				if not has_linux_do and not has_github and not has_cookies and not has_x666_token:
					print(f"❌ Account {i + 1} must have either 'linux.do', 'github', or 'cookies' configuration")
					return []

				if has_linux_do:
					auth_config = account['linux.do']
					if not isinstance(auth_config, dict):
						print(f"❌ Account {i + 1} linux.do configuration must be a dictionary")
						return []
					if 'username' not in auth_config or 'password' not in auth_config:
						print(f"❌ Account {i + 1} linux.do configuration must contain username and password")
						return []
					if not auth_config['username'] or not auth_config['password']:
						print(f"❌ Account {i + 1} linux.do username and password cannot be empty")
						return []

				if has_github:
					auth_config = account['github']
					if not isinstance(auth_config, dict):
						print(f"❌ Account {i + 1} github configuration must be a dictionary")
						return []
					if 'username' not in auth_config or 'password' not in auth_config:
						print(f"❌ Account {i + 1} github configuration must contain username and password")
						return []
					if not auth_config['username'] or not auth_config['password']:
						print(f"❌ Account {i + 1} github username and password cannot be empty")
						return []

				if has_cookies:
					cookies_config = account['cookies']
					if not cookies_config:
						print(f'❌ Account {i + 1} cookies cannot be empty')
						return []
					if 'api_user' not in account:
						print(f'❌ Account {i + 1} with cookies must have api_user field')
						return []
					if not account['api_user']:
						print(f'❌ Account {i + 1} api_user cannot be empty')
						return []

				if 'name' in account and not account['name']:
					print(f'❌ Account {i + 1} name field cannot be empty')
					return []

				accounts.append(AccountConfig.from_dict(account, i))

			return accounts
		except json.JSONDecodeError as exc:
			print(f'❌ Account configuration JSON format is incorrect: {exc}')
			return []
		except Exception as exc:
			print(f'❌ Account configuration format is incorrect: {exc}')
			return []

	def get_provider(self, name: str) -> ProviderConfig | None:
		"""获取指定 provider 配置"""
		return self.providers.get(name)

	def update_provider(self, site_name: str, provider: ProviderConfig) -> None:
		"""更新内存中的 provider / site definition"""
		self.providers[site_name] = provider
		if site_name in self.site_definitions:
			site_definition = self.site_definitions[site_name]
			self.site_definitions[site_name] = SiteDefinition(
				name=site_definition.name,
				provider=provider,
				checkin=site_definition.checkin,
				mode=site_definition.mode,
			)
