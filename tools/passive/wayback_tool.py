# Wayback 历史归档工具
# Wayback Machine + Common Crawl 多数据源历史归档查询
# 增强重试机制，自动降级到备选数据源

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


class WaybackTool(BaseTool):
    """
    Wayback Machine 历史归档查询工具

    多数据源降级方案：
    1. Wayback Machine (主要) - Internet Archive
    2. Common Crawl (备选) - 互联网爬虫数据集
    3. 增强重试机制，避免网络抖动
    """

    tool_name = "wayback"
    description = "Wayback 历史归档查询（多数据源降级）"
    timeout = 60  # 多次重试 + CommonCrawl 降级需要更长时间
    max_retries = 2
    cache_ttl = 3600
    is_passive = True

    # 敏感路径关键词（用于筛选历史 URL）
    SENSITIVE_KEYWORDS = [
        "admin", "login", "api", "backup", "config", "test",
        "dev", "staging", "phpmyadmin", "wp-admin", "manage",
    ]

    # 自定义 User-Agent
    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        执行历史归档查询（多数据源降级）

        优先使用 Wayback Machine，失败时自动降级到 Common Crawl
        """
        # 优先尝试 Wayback（只重试 1 次，避免总时间过长）
        wayback_result = await self._query_wayback_with_retry(target, max_retries=1)

        # 如果 wayback 没数据，降级到 Common Crawl
        if not wayback_result.get("urls"):
            cc_result = await self._query_commoncrawl(target)
            if cc_result.get("urls"):
                wayback_result["sources_used"] = wayback_result.get("sources_used", []) + ["commoncrawl"]
                wayback_result["urls"].extend(cc_result.get("urls", []))
                wayback_result["sensitive_paths"].extend(cc_result.get("sensitive_paths", []))
                wayback_result["count"] = len(wayback_result["urls"])
                wayback_result["cc_data"] = cc_result

        return wayback_result

    async def _query_wayback_with_retry(self, target: str, max_retries: int = 1) -> dict[str, Any]:
        """带重试机制的 Wayback 查询（最多 1 次重试，避免超时）"""
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit=1000"

        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                async with _create_httpx_client(20, self.DEFAULT_HEADERS) as client:
                    resp = await client.get(url)
                    resp.raise_for_status()

                    data = resp.json()
                    # 第一行是表头，跳过
                    urls = [row[0] for row in data[1:] if row]

                    # 提取敏感路径
                    sensitive = []
                    for u in urls:
                        path = u.split("/")[-1] if "/" in u else u
                        for kw in self.SENSITIVE_KEYWORDS:
                            if kw.lower() in u.lower():
                                sensitive.append({
                                    "url": u,
                                    "keyword": kw,
                                    "path": path,
                                    "source": "wayback",
                                })
                                break

                    return {
                        "domain": target,
                        "urls": urls[:100],
                        "sensitive_paths": sensitive[:20],
                        "count": len(urls),
                        "sources_used": ["wayback"],
                    }
            except Exception as e:
                last_error = str(e)

        return {
            "domain": target,
            "urls": [],
            "sensitive_paths": [],
            "count": 0,
            "sources_used": [],
            "error": f"Wayback 失败: {last_error}",
        }

    async def _query_commoncrawl(self, target: str) -> dict[str, Any]:
        """Common Crawl 备选数据源"""
        # Common Crawl 索引 API
        url = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{target}/*&output=json&limit=100"

        async with _create_httpx_client(self.timeout, self.DEFAULT_HEADERS) as client:
            try:
                resp = await client.get(url)
                resp.raise_for_status()

                urls = []
                for line in resp.text.strip().splitlines():
                    if not line:
                        continue
                    try:
                        import json
                        entry = json.loads(line)
                        if "url" in entry:
                            urls.append(entry["url"])
                    except Exception:
                        continue

                # 提取敏感路径
                sensitive = []
                for u in urls:
                    path = u.split("/")[-1] if "/" in u else u
                    for kw in self.SENSITIVE_KEYWORDS:
                        if kw.lower() in u.lower():
                            sensitive.append({
                                "url": u,
                                "keyword": kw,
                                "path": path,
                                "source": "commoncrawl",
                            })
                            break

                return {
                    "source": "commoncrawl",
                    "urls": urls[:100],
                    "sensitive_paths": sensitive[:20],
                    "count": len(urls),
                }
            except Exception as e:
                return {
                    "source": "commoncrawl",
                    "urls": [],
                    "sensitive_paths": [],
                    "count": 0,
                    "error": str(e),
                }
