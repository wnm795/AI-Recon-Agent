# DNS 枚举工具
# 全类型 DNS 记录异步并发查询，基于 dnspython 实现

import asyncio
from typing import Any

import dns.resolver

from tools.base import BaseTool


class DnsEnumTool(BaseTool):
    """
    DNS 记录枚举工具

    异步并发查询 A、AAAA、MX、NS、TXT、SOA、CNAME 记录
    """

    tool_name = "dns_enum"
    description = "DNS 记录枚举（A/AAAA/MX/NS/TXT/SOA/CNAME）"
    timeout = 10
    max_retries = 2
    cache_ttl = 3600
    is_passive = True

    # 查询的 DNS 记录类型
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行 DNS 枚举"""
        loop = asyncio.get_event_loop()

        # 并发查询所有记录类型
        tasks = [
            loop.run_in_executor(None, self._query_record, target, rtype)
            for rtype in self.RECORD_TYPES
        ]
        results = await asyncio.gather(*tasks)

        records = {}
        all_ips = []
        for rtype, result in zip(self.RECORD_TYPES, results):
            if result:
                records[rtype] = result
                if rtype == "A":
                    all_ips.extend(result)
                elif rtype == "AAAA":
                    all_ips.extend(result)

        return {
            "domain": target,
            "records": records,
            "ips": list(dict.fromkeys(all_ips)),
            "count": sum(len(v) for v in records.values()),
        }

    def _query_record(self, domain: str, rtype: str) -> list[str] | None:
        """同步查询单类 DNS 记录"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            answers = resolver.resolve(domain, rtype)
            results = []
            for rdata in answers:
                val = str(rdata)
                # MX 记录提取优先级和地址
                if rtype == "MX":
                    val = str(rdata.exchange)
                results.append(val)
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
            return None
