# CDN/WAF 识别工具
# 通过响应头 + IP 归属判断目标是否使用 CDN 或 WAF

from typing import Any

import httpx

from tools.base import BaseTool


class CdnDetectTool(BaseTool):
    """
    CDN/WAF 识别工具

    通过 HTTP 响应头特征和 IP 归属信息判断目标是否使用 CDN 或 WAF
    """

    tool_name = "cdn_detect"
    description = "CDN/WAF 识别"
    timeout = 15
    max_retries = 2
    cache_ttl = 3600
    is_passive = False

    # CDN 特征头
    CDN_HEADERS = [
        "cloudflare", "akamai", "fastly", "incapsula",
        "cloudfront", "maxcdn", "keycdn", "cdn77",
        "x-cdn", "x-cache", "via", "server",
    ]

    # WAF 特征头
    WAF_HEADERS = [
        "x-waf", "x-firewall", "mod_security",
        "aws-waf", "akamai-bot", "imperva",
    ]

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行 CDN/WAF 检测"""
        url = f"http://{target}" if not target.startswith("http") else target

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

                cdn_detected = False
                waf_detected = False
                cdn_provider = ""
                waf_provider = ""

                for header_name, header_value in headers.items():
                    for cdn in self.CDN_HEADERS:
                        if cdn in header_name or cdn in header_value:
                            cdn_detected = True
                            cdn_provider = cdn

                    for waf in self.WAF_HEADERS:
                        if waf in header_name or waf in header_value:
                            waf_detected = True
                            waf_provider = waf

                return {
                    "target": target,
                    "has_cdn": cdn_detected,
                    "cdn_provider": cdn_provider,
                    "has_waf": waf_detected,
                    "waf_provider": waf_provider,
                    "headers": dict(resp.headers),
                    "status_code": resp.status_code,
                }
            except Exception as e:
                return {
                    "target": target,
                    "has_cdn": False,
                    "has_waf": False,
                    "error": str(e),
                }
