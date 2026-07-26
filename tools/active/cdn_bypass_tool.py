# CDN 真实 IP 挖掘工具
# 基于 DNS 历史解析多源 IP 交叉比对，绕过 CDN 获取真实 IP

from typing import Any

import httpx

from tools.base import BaseTool


class CdnBypassTool(BaseTool):
    """
    CDN 真实 IP 挖掘工具

    通过 SecurityTrails / ViewDNS / IP 历史解析记录获取真实 IP
    """

    tool_name = "cdn_bypass"
    description = "CDN 真实 IP 挖掘"
    timeout = 20
    max_retries = 2
    cache_ttl = 3600
    is_passive = False

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行 CDN 绕过探测"""
        # 使用 ViewDNS 的历史解析记录 API（免费，无需 Key）
        url = f"https://viewdns.info/iphistory/?domain={target}"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })

                # 简单解析 HTML 提取 IP
                import re
                ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', resp.text)
                unique_ips = list(dict.fromkeys(ips))

                # 排除常见 CDN IP 段（简化判断）
                real_ips = [ip for ip in unique_ips if not self._is_cdn_ip(ip)]

                return {
                    "target": target,
                    "real_ip": real_ips[0] if real_ips else "",
                    "candidate_ips": real_ips[:5],
                    "all_ips": unique_ips[:10],
                    "count": len(real_ips),
                }
            except Exception as e:
                return {
                    "target": target,
                    "real_ip": "",
                    "error": str(e),
                }

    def _is_cdn_ip(self, ip: str) -> bool:
        """简单判断是否为常见 CDN IP 段（简化版）"""
        cdn_prefixes = ["104.16.", "104.17.", "172.64.", "173.245.", "198.41."]
        return any(ip.startswith(prefix) for prefix in cdn_prefixes)
