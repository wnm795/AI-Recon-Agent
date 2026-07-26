# GitHub 泄露检索工具
# GitHub API + searchcode + grep.app 多源代码泄露检索
# 任何源失败时自动降级到其他源

import asyncio
import os
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


class GithubLeakTool(BaseTool):
    """
    GitHub 泄露检索工具

    多源降级方案：
    1. GitHub Code Search API (主要) - 需要 GITHUB_TOKEN 提升速率
    2. searchcode.com (备选) - 公共代码搜索引擎
    3. grep.app (备选) - GitHub 代码实时检索
    """

    tool_name = "github_leak"
    description = "代码泄露检索（多源降级）"
    timeout = 60  # 多个源依次降级需要更长时间
    max_retries = 2
    cache_ttl = 3600
    is_passive = True

    # 搜索关键词模板
    SEARCH_QUERIES = [
        "api_key",
        "password",
        "secret",
        "token",
        "AKIA",  # AWS Access Key ID 前缀
    ]

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        执行代码泄露检索（多源降级）

        优先使用 GitHub API，失败时降级到 searchcode 和 grep.app
        """
        all_leaks = []
        sources_used = []
        errors = []

        # 1. 尝试 GitHub API（可使用 GITHUB_TOKEN 提升速率）
        github_token = os.getenv("GITHUB_TOKEN", "")
        github_result = await self._query_github(target, github_token)
        if github_result.get("leaks"):
            all_leaks.extend(github_result["leaks"])
            sources_used.append("github")
        elif github_result.get("error"):
            errors.append(f"github: {github_result['error']}")

        # 2. 降级到 searchcode.com
        if not all_leaks:
            searchcode_result = await self._query_searchcode(target)
            if searchcode_result.get("leaks"):
                all_leaks.extend(searchcode_result["leaks"])
                sources_used.append("searchcode")
            elif searchcode_result.get("error"):
                errors.append(f"searchcode: {searchcode_result['error']}")

        # 3. 降级到 grep.app
        if not all_leaks:
            grep_result = await self._query_grep_app(target)
            if grep_result.get("leaks"):
                all_leaks.extend(grep_result["leaks"])
                sources_used.append("grep.app")
            elif grep_result.get("error"):
                errors.append(f"grep.app: {grep_result['error']}")

        return {
            "domain": target,
            "leak_info": all_leaks,
            "count": len(all_leaks),
            "sources_used": sources_used,
            "errors": errors if errors else None,
        }

    async def _query_github(self, target: str, token: str = "") -> dict[str, Any]:
        """GitHub Code Search API"""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            **self.DEFAULT_HEADERS,
        }
        # 认证 token 可提升速率限制：5000/小时
        if token:
            headers["Authorization"] = f"token {token}"

        leaks = []
        async with _create_httpx_client(self.timeout, headers) as client:
            for keyword in self.SEARCH_QUERIES:
                query = f"{keyword} {target}"
                url = f"https://api.github.com/search/code?q={query}&per_page=5"

                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        items = data.get("items", [])
                        for item in items[:3]:
                            leaks.append({
                                "source": "github",
                                "type": keyword,
                                "repository": item.get("repository", {}).get("full_name", ""),
                                "path": item.get("path", ""),
                                "url": item.get("html_url", ""),
                            })
                    elif resp.status_code == 403:
                        # 速率限制
                        return {"leaks": leaks, "error": f"GitHub API 速率限制 (HTTP 403)，建议在 .env 配置 GITHUB_TOKEN"}
                    # 限流延迟
                    await asyncio.sleep(0.5)
                except Exception as e:
                    return {"leaks": leaks, "error": str(e)}

        return {"leaks": leaks, "error": None if leaks else "GitHub API 无结果"}

    async def _query_searchcode(self, target: str) -> dict[str, Any]:
        """searchcode.com 公共代码搜索"""
        leaks = []

        async with _create_httpx_client(self.timeout, self.DEFAULT_HEADERS) as client:
            for keyword in self.SEARCH_QUERIES[:3]:  # 只取前 3 个关键词
                url = f"https://searchcode.com/api/codesearch_I/?q={keyword}+{target}&per_page=5"

                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        results = data.get("results", [])
                        for item in results[:3]:
                            leaks.append({
                                "source": "searchcode",
                                "type": keyword,
                                "repository": item.get("repo", ""),
                                "path": item.get("filename", ""),
                                "url": item.get("url", ""),
                            })
                    await asyncio.sleep(0.5)
                except Exception as e:
                    return {"leaks": leaks, "error": str(e)}

        return {"leaks": leaks, "error": None if leaks else "searchcode 无结果"}

    async def _query_grep_app(self, target: str) -> dict[str, Any]:
        """grep.app GitHub 代码实时检索"""
        leaks = []

        async with _create_httpx_client(self.timeout, self.DEFAULT_HEADERS) as client:
            for keyword in self.SEARCH_QUERIES[:3]:
                url = f"https://grep.app/api/search?q={keyword}+{target}&regexp=false"

                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        hits = data.get("hits", {}).get("hits", [])
                        for item in hits[:3]:
                            repo = item.get("repo", {})
                            leaks.append({
                                "source": "grep.app",
                                "type": keyword,
                                "repository": repo.get("raw", ""),
                                "path": item.get("content", {}).get("path", ""),
                                "url": f"https://grep.app/search?q={keyword}+{target}",
                            })
                    await asyncio.sleep(0.5)
                except Exception as e:
                    return {"leaks": leaks, "error": str(e)}

        return {"leaks": leaks, "error": None if leaks else "grep.app 无结果"}
