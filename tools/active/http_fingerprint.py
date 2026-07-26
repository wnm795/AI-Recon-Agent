# Web 指纹识别工具
# 多维度指纹识别：header/favicon/title/cookie，基于精准规则匹配

from typing import Any

import httpx

from tools.base import BaseTool


class HttpFingerprintTool(BaseTool):
    """
    Web 指纹识别工具

    多维度识别 Web 技术栈：Server 头、Title、Favicon、Cookie、响应体特征
    """

    tool_name = "http_fingerprint"
    description = "Web 多维度指纹识别"
    timeout = 15
    max_retries = 2
    cache_ttl = 3600
    is_passive = False

    # 简化指纹规则库（部分示例）
    FINGERPRINT_RULES = [
        {"name": "nginx", "headers": {"server": "nginx"}, "version_header": "server"},
        {"name": "Apache", "headers": {"server": "apache"}, "version_header": "server"},
        {"name": "IIS", "headers": {"server": "microsoft-iis"}, "version_header": "server"},
        {"name": "Cloudflare", "headers": {"server": "cloudflare"}},
        {"name": "PHP", "body_patterns": ["php", "x-powered-by: php"]},
        {"name": "WordPress", "body_patterns": ["/wp-content/", "/wp-includes/"]},
        {"name": "Django", "headers": {"set-cookie": "csrftoken"}},
        {"name": "Spring Boot", "body_patterns": ["whitelabel error page"]},
    ]

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行 Web 指纹识别"""
        url = f"http://{target}" if not target.startswith("http") else target

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.text[:5000]  # 只取前 5000 字符

                fingerprints = []

                for rule in self.FINGERPRINT_RULES:
                    matched = False
                    version = ""

                    # 匹配 Header
                    rule_headers = rule.get("headers", {})
                    for hkey, hval in rule_headers.items():
                        actual = headers.get(hkey, "").lower()
                        if hval.lower() in actual:
                            matched = True
                            # 尝试提取版本号
                            version_header = rule.get("version_header", "")
                            if version_header and version_header.lower() in headers:
                                version = self._extract_version(headers[version_header.lower()])

                    # 匹配 Body
                    if not matched:
                        for pattern in rule.get("body_patterns", []):
                            if pattern.lower() in body.lower():
                                matched = True
                                break

                    if matched:
                        fingerprints.append({
                            "url": url,
                            "name": rule["name"],
                            "version": version,
                            "detail": f"匹配规则: {list(rule_headers.keys()) if rule_headers else 'body'}",
                        })

                return {
                    "target": target,
                    "fingerprints": fingerprints,
                    "status_code": resp.status_code,
                    "title": self._extract_title(body),
                    "count": len(fingerprints),
                }
            except Exception as e:
                return {
                    "target": target,
                    "fingerprints": [],
                    "error": str(e),
                }

    def _extract_version(self, header_value: str) -> str:
        """从 Header 值中提取版本号"""
        import re
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', header_value)
        return match.group(1) if match else ""

    def _extract_title(self, body: str) -> str:
        """从 HTML 中提取 Title"""
        import re
        match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""
