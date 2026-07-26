# 证书日志挖掘工具
# 基于 crt.sh + certspotter 多 API 证书透明度日志查询
# crt.sh 不可用时自动降级到 certspotter

import asyncio
import ssl
from typing import Any

import httpx

from tools.base import BaseTool


def _create_httpx_client(timeout: int, headers: dict) -> httpx.AsyncClient:
    """创建 httpx 客户端，禁用 SSL 验证以应对证书问题"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return httpx.AsyncClient(
        timeout=timeout,
        headers=headers,
        verify=ssl_context,
        follow_redirects=True,
    )


class CertLogTool(BaseTool):
    """
    证书透明度日志子域名挖掘工具

    多 API 降级方案：
    1. crt.sh (主要) - 免费证书查询
    2. certspotter (备选) - 由 SSLMate 提供
    3. facebook CT (备选) - Meta 证书透明度监控
    """

    tool_name = "cert_log"
    description = "证书透明度日志子域名挖掘（多 API 降级）"
    timeout = 60  # 多 API 并行调用需要更长时间
    max_retries = 2
    cache_ttl = 3600
    is_passive = True

    # 自定义 User-Agent（部分服务拒绝默认 UA）
    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        执行证书日志查询（多 API 并行降级）

        优先使用 crt.sh，失败时自动降级到 certspotter、facebook CT
        """
        # 并行调用多个 API
        tasks = [
            self._query_crtsh(target),
            self._query_certspotter(target),
            self._query_facebook_ct(target),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_subdomains = set()
        sources_used = []
        errors = []

        for result in results:
            if isinstance(result, dict):
                if result.get("subdomains"):
                    all_subdomains.update(result["subdomains"])
                    sources_used.append(result.get("source", "unknown"))
                elif result.get("error"):
                    errors.append(f"{result.get('source', 'unknown')}: {result['error']}")

        return {
            "domain": target,
            "subdomains": sorted(all_subdomains),
            "count": len(all_subdomains),
            "sources_used": sources_used,
            "errors": errors if errors else None,
        }

    async def _query_crtsh(self, target: str) -> dict[str, Any]:
        """crt.sh 证书透明度查询"""
        url = f"https://crt.sh/?q=%.{target}&output=json"

        async with _create_httpx_client(self.timeout, self.DEFAULT_HEADERS) as client:
            try:
                resp = await client.get(url)
                resp.raise_for_status()

                data = resp.json()
                subdomains = set()

                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and not name.startswith("*") and "." in name:
                            subdomains.add(name)

                return {
                    "source": "crtsh",
                    "subdomains": list(subdomains),
                    "count": len(subdomains),
                }
            except Exception as e:
                return {"source": "crtsh", "subdomains": [], "error": str(e)}

    async def _query_certspotter(self, target: str) -> dict[str, Any]:
        """certspotter 证书查询（SSLMate 提供，免费）"""
        url = f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names"

        async with _create_httpx_client(self.timeout, self.DEFAULT_HEADERS) as client:
            try:
                resp = await client.get(url)
                resp.raise_for_status()

                subdomains = set()
                for entry in resp.json():
                    for name in entry.get("dns_names", []):
                        name = name.strip().lower()
                        if name and not name.startswith("*") and "." in name:
                            subdomains.add(name)

                return {
                    "source": "certspotter",
                    "subdomains": list(subdomains),
                    "count": len(subdomains),
                }
            except Exception as e:
                return {"source": "certspotter", "subdomains": [], "error": str(e)}

    async def _query_facebook_ct(self, target: str) -> dict[str, Any]:
        """Facebook 证书透明度监控（Meta 提供，免费）"""
        url = f"https://graph.facebook.com/v1.0/certificates?query={target}&fields=subject_name,dns_names&limit=1000&access_token=public"

        async with _create_httpx_client(self.timeout, self.DEFAULT_HEADERS) as client:
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return {"source": "facebook_ct", "subdomains": [], "error": f"HTTP {resp.status_code}"}

                data = resp.json()
                subdomains = set()

                for entry in data.get("data", []):
                    for name in entry.get("dns_names", []):
                        name = name.strip().lower()
                        if name and not name.startswith("*") and "." in name:
                            subdomains.add(name)

                return {
                    "source": "facebook_ct",
                    "subdomains": list(subdomains),
                    "count": len(subdomains),
                }
            except Exception as e:
                return {"source": "facebook_ct", "subdomains": [], "error": str(e)}
