# 子域名挖掘工具
# 结合 subfinder + crt.sh 批量挖掘子域名，结果自动去重
# subfinder 不可用时自动降级到 crt.sh API

import asyncio
import json
import shutil
import subprocess
from typing import Any

import httpx

from tools.base import BaseTool
from config.settings import RATE_LIMIT_PER_SECOND


class SubdomainTool(BaseTool):
    """
    子域名批量挖掘工具

    优先使用 subfinder 命令行工具，不可用时降级到 crt.sh API
    结果自动去重
    """

    tool_name = "subdomain"
    description = "批量挖掘目标子域名，优先 subfinder，降级 crt.sh API"
    timeout = 60
    max_retries = 2
    cache_ttl = 3600
    is_passive = True

    # 运行时检测 subfinder 是否可用
    _subfinder_available: bool | None = None

    @classmethod
    def is_subfinder_available(cls) -> bool:
        """检测 subfinder 是否已安装"""
        if cls._subfinder_available is None:
            cls._subfinder_available = shutil.which("subfinder") is not None
        return cls._subfinder_available

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        执行子域名挖掘

        Args:
            target: 目标域名
            params: 额外参数

        Returns:
            {"subdomains": ["sub1.example.com", ...], "source": "subfinder|multi_api"}
        """
        # 提取主域名（去掉 www. 前缀）
        domain = target.strip().lower()
        if domain.startswith("www."):
            domain = domain[4:]

        # 内部给 subfinder 设置较短超时（避免在 BaseTool 60s 外层超时里耗时太久）
        # subfinder 找不到结果时降级到 multi_api
        if self.is_subfinder_available():
            try:
                result = await asyncio.wait_for(
                    self._run_subfinder(domain),
                    timeout=20,  # subfinder 单独最多 20s
                )
                # 如果 subfinder 返回有效结果（哪怕只有 1 个），直接用
                if result.get("subdomains") and len(result["subdomains"]) > 0:
                    return result
            except (asyncio.TimeoutError, Exception):
                # subfinder 失败/超时，降级到 multi_api
                pass

        # 降级到多 API 方案（带内部超时控制）
        try:
            return await asyncio.wait_for(
                self._run_multi_api_fallback(domain),
                timeout=45,  # 4 个 API 并发最多 45s
            )
        except asyncio.TimeoutError:
            return {
                "subdomains": [],
                "source": "multi_api_timeout",
                "count": 0,
                "error": "所有子域名 API 均超时，未能获取结果",
            }

    async def _run_subfinder(self, domain: str) -> dict[str, Any]:
        """
        调用 subfinder 命令行工具

        命令: subfinder -d domain -oJ -silent
        -oJ 输出 JSON 格式（每行一个 JSON 对象）
        -silent 仅输出结果不显示 banner
        """
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            self._run_subfinder_sync,
            domain,
        )
        return result

    def _run_subfinder_sync(self, domain: str) -> dict[str, Any]:
        """同步执行 subfinder（在线程池中调用）"""
        try:
            proc = subprocess.run(
                ["subfinder", "-d", domain, "-oJ", "-silent"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                encoding="utf-8",
                errors="replace",
            )

            subdomains = set()
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # subfinder -oJ 每行输出格式: {"host": "sub.example.com", ...}
                    try:
                        obj = json.loads(line)
                        host = obj.get("host", "")
                        if host:
                            subdomains.add(host.lower())
                    except json.JSONDecodeError:
                        # 非JSON行，直接作为域名处理
                        if line and "." in line:
                            subdomains.add(line.lower())

            return {
                "subdomains": sorted(subdomains),
                "source": "subfinder",
                "count": len(subdomains),
            }

        except subprocess.TimeoutExpired:
            raise TimeoutError(f"subfinder 执行超时（{self.timeout}s）")
        except FileNotFoundError:
            # subfinder 不存在，降级
            import asyncio
            return asyncio.get_event_loop().run_until_complete(self._run_crtsh(domain))

    async def _run_multi_api_fallback(self, domain: str) -> dict[str, Any]:
        """
        多 API 降级方案：组合多个免费子域名发现服务
        包括: crt.sh, hackertarget, threatcrowd, certspotter
        """
        all_subdomains = set()
        sources = []

        api_tasks = [
            self._run_crtsh(domain),
            self._run_hackertarget(domain),
            self._run_threatcrowd(domain),
            self._run_certspotter(domain),
        ]

        results = await asyncio.gather(*api_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result.get("subdomains"):
                all_subdomains.update(result["subdomains"])
                sources.append(result.get("source", "unknown"))

        return {
            "subdomains": sorted(all_subdomains),
            "source": "multi_api(" + ",".join(sources) + ")",
            "count": len(all_subdomains),
            "sources_used": sources,
        }

    async def _run_crtsh(self, domain: str) -> dict[str, Any]:
        """
        通过 crt.sh API 查询证书日志挖掘子域名
        """
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url)
            resp.raise_for_status()

            subdomains = set()
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and not name.startswith("*") and "." in name:
                        subdomains.add(name)

            return {
                "subdomains": sorted(subdomains),
                "source": "crtsh",
                "count": len(subdomains),
            }

    async def _run_hackertarget(self, domain: str) -> dict[str, Any]:
        """
        通过 hackertarget.com API 查询子域名
        """
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url)
            resp.raise_for_status()

            subdomains = set()
            for line in resp.text.strip().splitlines():
                parts = line.split(",")
                if len(parts) >= 1:
                    sub = parts[0].strip().lower()
                    if sub and "." in sub:
                        subdomains.add(sub)

            return {
                "subdomains": sorted(subdomains),
                "source": "hackertarget",
                "count": len(subdomains),
            }

    async def _run_threatcrowd(self, domain: str) -> dict[str, Any]:
        """
        通过 threatcrowd.org API 查询子域名
        """
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url)
            resp.raise_for_status()

            data = resp.json()
            subdomains = set()
            for sub in data.get("subdomains", []):
                sub = sub.strip().lower()
                if sub and "." in sub:
                    subdomains.add(sub)

            return {
                "subdomains": sorted(subdomains),
                "source": "threatcrowd",
                "count": len(subdomains),
            }

    async def _run_certspotter(self, domain: str) -> dict[str, Any]:
        """
        通过 certspotter.com API 查询证书日志
        """
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url)
            resp.raise_for_status()

            subdomains = set()
            for entry in resp.json():
                for name in entry.get("dns_names", []):
                    name = name.strip().lower()
                    if name and not name.startswith("*") and "." in name:
                        subdomains.add(name)

            return {
                "subdomains": sorted(subdomains),
                "source": "certspotter",
                "count": len(subdomains),
            }