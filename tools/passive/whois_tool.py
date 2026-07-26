# WHOIS 查询工具
# 域名注册信息查询，内置缓存 1h、10s 超时、2 次重试机制

import asyncio
import ipaddress
import re
import socket
import whois
from datetime import datetime
from typing import Any

import httpx

from tools.base import BaseTool


def _is_ip_address(target: str) -> bool:
    """判断目标是否为 IP 地址"""
    try:
        ipaddress.ip_address(target.strip())
        return True
    except (ValueError, AttributeError):
        return False


def _extract_domain_from_target(target: str) -> str:
    """从 target 中提取域名（处理 URL/带路径/端口等情况）"""
    if not target:
        return ""
    text = target.strip().lower()
    # 去掉协议头
    text = re.sub(r'^https?://', '', text)
    # 去掉路径
    text = text.split('/', 1)[0]
    # 去掉端口
    text = text.split(':', 1)[0]
    # 去掉 www. 前缀（whois 库对小写 .com 友好）
    if text.startswith('www.'):
        text = text[4:]
    return text


class WhoisTool(BaseTool):
    """
    WHOIS 域名注册信息查询工具

    依赖: python-whois
    内置特性: 缓存 1h、60s 超时、3 次重试
    """

    tool_name = "whois"
    description = "查询域名注册信息，包括注册商、注册日期、过期日期、DNS 服务器等"
    timeout = 60
    max_retries = 3
    cache_ttl = 3600
    is_passive = True

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        执行 WHOIS 查询

        Args:
            target: 目标域名/IP/URL
            params: 额外参数（当前未使用）

        Returns:
            标准化的 WHOIS 信息字典
        """
        # 1. 提取纯域名（去除协议/路径/端口）
        domain = _extract_domain_from_target(target)
        if not domain:
            return {
                "domain": target,
                "error": "无法从目标中提取有效域名",
                "skip_reason": "invalid_target",
            }

        # 2. 如果提取后是 IP 地址（说明原始 target 是 URL 形式或裸 IP），走 IP WHOIS 路径
        if _is_ip_address(domain):
            return await self._whois_for_ip(domain)

        # 3. 走域名 WHOIS 路径
        # whois 库是同步阻塞的，放到线程池中执行避免阻塞事件循环
        loop = asyncio.get_event_loop()

        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_whois, domain),
                timeout=30,
            )
            return result
        except asyncio.TimeoutError:
            # 超时后尝试使用 HTTP API 作为降级方案
            return await self._fallback_whois_http(domain)
        except Exception as e:
            # python-whois 库自身异常（如 WhoisError、socket.gaierror）
            # 捕获后降级到 HTTP API
            error_msg = f"{type(e).__name__}: {e}"
            try:
                fallback = await self._fallback_whois_http(domain)
                if fallback and not fallback.get("error"):
                    fallback["original_error"] = error_msg
                return fallback
            except Exception:
                return {
                    "domain": domain,
                    "error": f"WHOIS 查询失败: {error_msg}",
                    "skip_reason": "whois_failed",
                }

    async def _whois_for_ip(self, ip: str) -> dict[str, Any]:
        """IP 地址专用 WHOIS：使用 IP-API 获取归属信息"""
        # 内网 IP 检测：IP-API 不支持内网 IP，提前返回网络段信息
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return {
                    "domain": ip,
                    "target_type": "ip",
                    "ip_version": ip_obj.version,
                    "is_private": True,
                    "ip_class": "private" if ip_obj.is_private else (
                        "loopback" if ip_obj.is_loopback else "reserved"
                    ),
                    "source": "local_detection",
                    "note": "目标为内网 IP，IP-API 不提供此类查询；建议进行端口扫描、目录爆破、指纹识别等主动探测",
                }
        except (ValueError, AttributeError):
            pass

        async with httpx.AsyncClient(timeout=15) as client:
            try:
                url = f"http://ip-api.com/json/{ip}?fields=status,message,org,as,country,regionName,city,zip,lat,lon,timezone,isp,reverse,query,hosting"
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        # 即使部分字段为 None，也返回有数据的部分
                        result = {
                            "domain": ip,
                            "target_type": "ip",
                            "org": data.get("org") or "",
                            "isp": data.get("isp") or "",
                            "as": data.get("as") or "",
                            "country": data.get("country") or "",
                            "region": data.get("regionName") or "",
                            "city": data.get("city") or "",
                            "reverse": data.get("reverse") or "",
                            "hosting": data.get("hosting", False),
                            "source": "ip_api",
                        }
                        # 过滤空字符串，但保留 hosting 布尔字段
                        return {k: v for k, v in result.items() if v or k == "hosting"}
                    return {
                        "domain": ip,
                        "target_type": "ip",
                        "error": data.get("message", "IP 查询失败"),
                        "skip_reason": "ip_api_failed",
                    }
            except Exception as e:
                return {
                    "domain": ip,
                    "target_type": "ip",
                    "error": f"IP WHOIS 查询失败: {e}",
                    "skip_reason": "ip_api_exception",
                }

        return {
            "domain": ip,
            "target_type": "ip",
            "error": "IP WHOIS 不可用",
        }

    def _sync_whois(self, domain: str) -> dict[str, Any]:
        """
        同步执行 WHOIS 查询（内部方法）

        Args:
            domain: 目标域名

        Returns:
            标准化的 WHOIS 信息字典
        """
        # 设置 socket 超时
        import socket
        socket.setdefaulttimeout(20)

        raw = whois.whois(domain)

        # 恢复默认超时
        socket.setdefaulttimeout(None)

        # 提取关键字段，处理 datetime 序列化
        def serialize(value):
            if isinstance(value, datetime):
                return value.isoformat()
            if isinstance(value, list):
                return [serialize(v) for v in value]
            return value

        data = {
            "domain": domain,
            "registrar": serialize(getattr(raw, "registrar", None)),
            "creation_date": serialize(getattr(raw, "creation_date", None)),
            "expiration_date": serialize(getattr(raw, "expiration_date", None)),
            "updated_date": serialize(getattr(raw, "updated_date", None)),
            "name_servers": serialize(getattr(raw, "name_servers", None)),
            "status": serialize(getattr(raw, "status", None)),
            "dnssec": serialize(getattr(raw, "dnssec", None)),
            "emails": serialize(getattr(raw, "emails", None)),
            "org": serialize(getattr(raw, "org", None)),
            "country": serialize(getattr(raw, "country", None)),
        }

        # 清理 None 值，减少无效数据
        return {k: v for k, v in data.items() if v is not None}

    async def _fallback_whois_http(self, domain: str) -> dict[str, Any]:
        """
        HTTP API 降级方案：使用 freewhois.com API 查询 WHOIS 信息
        """
        # 提取主域名（去掉 www. 前缀）
        query_domain = domain.lower()
        if query_domain.startswith("www."):
            query_domain = query_domain[4:]

        async with httpx.AsyncClient(timeout=15) as client:
            try:
                # 使用 freewhois.com API
                url = f"https://api.freewhois.com/json?q={query_domain}"
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    result = {
                        "domain": domain,
                        "registrar": data.get("registrar"),
                        "creation_date": data.get("created"),
                        "expiration_date": data.get("expires"),
                        "updated_date": data.get("updated"),
                        "name_servers": data.get("nameservers"),
                        "status": data.get("status"),
                        "source": "freewhois_api",
                    }
                    return {k: v for k, v in result.items() if v is not None}
            except Exception:
                pass

            try:
                # 使用 ip-api.com 作为备选（主要用于 IP，域名可能有限）
                url = f"http://ip-api.com/json/{query_domain}?fields=status,message,org,as,country,regionName,city,zip,lat,lon,timezone,isp,reverse,query"
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        return {
                            "domain": domain,
                            "org": data.get("org"),
                            "isp": data.get("isp"),
                            "country": data.get("country"),
                            "source": "ip_api",
                        }
            except Exception:
                pass

        return {
            "domain": domain,
            "error": "WHOIS 查询超时，HTTP 降级方案也失败",
        }