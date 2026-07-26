# API 接口发现工具
# 页面 JS 接口提取，基于正则批量匹配潜在 API 端点

import re
from typing import Any

import httpx

from tools.base import BaseTool


class ApiDiscoverTool(BaseTool):
    """
    API 接口发现工具

    爬取目标页面 JS 文件，通过正则匹配提取潜在的 API 端点
    """

    tool_name = "api_discover"
    description = "页面 JS 接口提取与 API 发现"
    timeout = 20
    max_retries = 2
    cache_ttl = 3600
    is_passive = False

    # API 端点正则模式
    API_PATTERNS = [
        re.compile(r'["\']((?:/api/|/v\d+/|/rest/)[^"\']+)["\']'),
        re.compile(r'["\']((?:GET|POST|PUT|DELETE|PATCH)\s+(/[^"\']+))["\']', re.I),
        re.compile(r'url\s*[:=]\s*["\']([^"\']*(?:api|graphql|rest)[^"\']*)["\']', re.I),
        re.compile(r'fetch\(["\']([^"\']+)["\']'),
        re.compile(r'axios\.[a-z]+\(["\']([^"\']+)["\']'),
    ]

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行 API 发现"""
        url = f"http://{target}" if not target.startswith("http") else target

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
                body = resp.text

                # 提取 JS 文件 URL
                js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body)
                # 补全相对路径
                full_js_urls = []
                for js in js_urls:
                    if js.startswith("http"):
                        full_js_urls.append(js)
                    elif js.startswith("/"):
                        base = f"{url.rstrip('/')}"
                        full_js_urls.append(base + js)
                    else:
                        full_js_urls.append(f"{url.rstrip('/')}/{js}")

                # 从主页面提取 API
                apis = self._extract_apis(body)

                # 从 JS 文件提取 API（取前 3 个）
                for js_url in full_js_urls[:3]:
                    try:
                        js_resp = await client.get(js_url)
                        apis.extend(self._extract_apis(js_resp.text))
                    except Exception:
                        continue

                # 去重
                unique_apis = list({a["endpoint"]: a for a in apis}.values())

                return {
                    "target": target,
                    "apis": unique_apis,
                    "count": len(unique_apis),
                }
            except Exception as e:
                return {
                    "target": target,
                    "apis": [],
                    "error": str(e),
                }

    def _extract_apis(self, text: str) -> list[dict]:
        """从文本中提取 API 端点"""
        apis = []
        seen = set()

        for pattern in self.API_PATTERNS:
            for match in pattern.finditer(text):
                endpoint = match.group(1)
                if endpoint and endpoint not in seen:
                    seen.add(endpoint)
                    apis.append({
                        "endpoint": endpoint,
                        "source": "regex",
                        "method": "GET",  # 默认方法
                    })

        return apis
