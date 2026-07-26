# ICP 备案查询工具
# 企业备案信息抓取，支持限流与缓存

from typing import Any

import httpx

from tools.base import BaseTool


class IcpTool(BaseTool):
    """
    ICP 备案查询工具

    通过 ICP 备案查询 API 获取域名备案信息
    当前使用公共 API 示例实现
    """

    tool_name = "icp"
    description = "ICP 备案信息查询"
    timeout = 15
    max_retries = 2
    cache_ttl = 86400
    is_passive = True

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行 ICP 查询"""
        # 使用 beian.miit.gov.cn 的公开查询接口
        # 实际环境中可能需要使用商业 API 或自行抓取
        url = f"https://api.vvhan.com/api/icp?url={target}"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("success"):
                        info = data.get("info", {})
                        return {
                            "domain": target,
                            "icp": info.get("icp", ""),
                            "company": info.get("name", ""),
                            "nature": info.get("nature", ""),
                            "title": info.get("title", ""),
                            "time": info.get("time", ""),
                        }
            except Exception:
                pass

        # 查询失败返回空结果（ICP 查询不应阻塞流程）
        return {
            "domain": target,
            "icp": "",
            "company": "",
            "note": "ICP 查询失败或该域名无备案信息",
        }
