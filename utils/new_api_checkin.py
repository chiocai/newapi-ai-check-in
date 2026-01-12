#!/usr/bin/env python3
"""
New-API 通用签到模块

适用于所有基于 New-API 的站点，签到 API 格式统一为：
POST /api/user/checkin
Header: New-Api-User: {用户ID} 或 {api_user_key}: {用户ID}
"""

import httpx
from utils.http_utils import response_resolve


def new_api_checkin(
	account_name: str,
	origin: str,
	api_user: str | int,
	headers: dict,
	cookies: dict,
	proxy: dict | None = None,
	api_user_key: str = "new-api-user",
	checkin_path: str = "/api/user/checkin",
) -> dict:
	"""执行 New-API 通用签到

	Args:
		account_name: 账号名称（用于日志）
		origin: 站点域名，如 https://runanytime.hxi.me
		api_user: 用户 ID
		headers: 请求头
		cookies: cookies 字典
		proxy: 代理配置
		api_user_key: 用户 ID 的 header key，默认为 "new-api-user"
		checkin_path: 签到 API 路径，默认为 "/api/user/checkin"

	Returns:
		dict: 包含 success, message, already_checked 等信息
	"""
	checkin_url = f"{origin}{checkin_path}"

	print(f"🌐 {account_name}: Executing New-API checkin at {checkin_url}")

	# 构建签到请求头
	checkin_headers = headers.copy()
	checkin_headers.update({
		"Content-Type": "application/json",
		"X-Requested-With": "XMLHttpRequest",
		api_user_key: str(api_user),
	})

	try:
		with httpx.Client(http2=True, timeout=30.0, proxy=proxy) as client:
			client.cookies.update(cookies)

			response = client.post(checkin_url, headers=checkin_headers, timeout=30)

			print(f"📨 {account_name}: Checkin response status {response.status_code}")

			if response.status_code == 200:
				json_data = response_resolve(response, "new_api_checkin", account_name)
				if json_data is None:
					return {
						"success": False,
						"error": "Invalid response format",
					}

				message = json_data.get("message", "")
				success = json_data.get("success", False)

				if success:
					print(f"✅ {account_name}: Checkin successful - {message}")
					return {
						"success": True,
						"message": message,
						"already_checked": False,
					}
				elif "已签到" in message or "already" in message.lower():
					print(f"ℹ️ {account_name}: Already checked in today - {message}")
					return {
						"success": True,
						"message": message,
						"already_checked": True,
					}
				else:
					print(f"❌ {account_name}: Checkin failed - {message}")
					return {
						"success": False,
						"error": message,
					}
			else:
				print(f"❌ {account_name}: Checkin failed - HTTP {response.status_code}")
				return {
					"success": False,
					"error": f"HTTP {response.status_code}",
				}

	except Exception as e:
		print(f"❌ {account_name}: Checkin error - {e}")
		return {
			"success": False,
			"error": str(e),
		}
