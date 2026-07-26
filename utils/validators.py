# 输入校验工具模块
# 域名/IP/URL 格式校验，确保扫描目标合法有效

import re


# 域名正则（简化版，支持中文域名 punycode）
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

# IP 地址正则
IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# URL 正则（简化版）
URL_PATTERN = re.compile(
    r'^https?://[^\s/$.?#].[^\s]*$',
    re.IGNORECASE,
)


def is_valid_domain(value: str) -> bool:
    """校验是否为合法域名"""
    if not value or len(value) > 253:
        return False
    return bool(DOMAIN_PATTERN.match(value))


def is_valid_ip(value: str) -> bool:
    """校验是否为合法 IPv4 地址"""
    if not value or not IP_PATTERN.match(value):
        return False
    # 进一步校验每段范围
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not 0 <= int(part) <= 255:
            return False
    return True


def is_valid_url(value: str) -> bool:
    """校验是否为合法 URL"""
    return bool(URL_PATTERN.match(value))


def detect_target_type(value: str) -> str:
    """
    自动检测目标类型

    Returns:
        "domain" | "ip" | "url" | "unknown"
    """
    if is_valid_url(value):
        return "url"
    if is_valid_ip(value):
        return "ip"
    if is_valid_domain(value):
        return "domain"
    return "unknown"


def sanitize_target(value: str) -> str:
    """
    清理目标字符串，去除常见前缀和多余空格
    """
    value = value.strip().lower()
    # 去除协议前缀
    if value.startswith("http://"):
        value = value[7:]
    elif value.startswith("https://"):
        value = value[8:]
    # 去除路径
    if "/" in value:
        value = value.split("/")[0]
    # 去除端口
    if ":" in value:
        value = value.split(":")[0]
    return value
