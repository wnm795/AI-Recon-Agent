# 被动工具并发执行节点
# 提取 task_list 中所有被动工具，通过注册表获取实例，asyncio.gather 批量并发执行

import asyncio
import re
from typing import Any

from config.settings import MAX_CONCURRENT_PASSIVE_TOOLS
from tools.registry import get_tool

IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')


def is_valid_ip(address: str) -> bool:
    return bool(IP_PATTERN.match(address))


# 被动工具白名单（根据 is_passive 属性也可判断）
PASSIVE_TOOLS = {
    "whois", "dns_enum", "subdomain", "icp",
    "github_leak", "wayback", "cert_log",
}


def passive_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    并发执行所有被动信息收集工具

    从 task_list 中筛选被动工具，使用 asyncio.gather 并发执行
    """
    target = state.get("target", "")
    task_list = state.get("task_list", [])
    skip_cache = state.get("skip_cache", False)

    if not target or not task_list:
        return {
            "current_phase": "passive",
            "messages": ["[passive] 无目标或任务，跳过被动扫描"],
        }

    # 筛选被动工具
    passive_tasks = [t for t in task_list if t in PASSIVE_TOOLS]

    if not passive_tasks:
        return {
            "current_phase": "passive",
            "completed_tasks": [],  # 明确返回空列表
            "messages": ["[passive] task_list 中无被动工具，跳过"],
        }

    # 并发执行
    results = asyncio.run(_run_passive_tools(target, passive_tasks, skip_cache))

    # 收集结果
    all_subdomains = []
    all_ips = []
    all_leaks = []
    whois_info = {}
    dns_records = []
    icp_info = {}
    completed = []
    errors = []
    messages = []

    for tool_name, result in zip(passive_tasks, results):
        if result.success and result.data:
            completed.append(tool_name)
            messages.append(f"[passive] {tool_name} 成功, 耗时: {result.elapsed:.2f}s")

            # 提取各类资产
            data = result.data
            if "subdomains" in data:
                all_subdomains.extend(data["subdomains"])
            if "ips" in data:
                for ip in data["ips"]:
                    if is_valid_ip(ip):
                        all_ips.append(ip)
            if "leak_info" in data:
                all_leaks.extend(data["leak_info"])
            if tool_name == "whois" and data:
                # 保存 WHOIS 信息（排除 source 字段、error 字段、skip_reason 字段）
                # 如果只有 error（无有效数据），不保存（避免报告里出现"error: xxx"）
                meaningful = {k: v for k, v in data.items()
                              if k not in ("source", "error", "skip_reason")
                              and v not in (None, "", [], {})}
                if meaningful and not data.get("skip_reason"):
                    whois_info = meaningful
            if tool_name == "dns_enum" and data.get("records"):
                dns_records = data["records"]
            if tool_name == "icp" and data:
                icp_info = data
        else:
            errors.append(f"{tool_name}: {result.error}")
            messages.append(f"[passive] {tool_name} 失败: {result.error}")

    # 过滤并去重子域名（只保留与目标相关的子域名）
    all_subdomains = _filter_valid_subdomains(all_subdomains, target)
    all_ips = list(dict.fromkeys(all_ips))

    updates: dict[str, Any] = {
        "current_phase": "passive",
        "completed_tasks": completed,
        "messages": messages,
        "skip_cache": skip_cache,
    }

    if all_subdomains:
        updates["subdomains"] = all_subdomains
        updates["discovered_assets"] = all_subdomains
    if all_ips:
        updates["ips"] = all_ips
    if all_leaks:
        updates["leak_info"] = all_leaks
    if whois_info:
        updates["whois_info"] = whois_info
    if dns_records:
        updates["dns_records"] = dns_records
    if icp_info:
        updates["icp_info"] = icp_info
    if errors:
        updates["errors"] = errors

    return updates


async def _run_passive_tools(target: str, tool_names: list[str], skip_cache: bool = False) -> list[Any]:
    """并发运行被动工具（带并发数限制）"""
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PASSIVE_TOOLS)

    async def run_one(name: str):
        async with semaphore:
            tool = get_tool(name)
            if not tool:
                return _fake_error_result(f"工具 {name} 未注册")
            return await tool.execute(target, params={"skip_cache": skip_cache})

    tasks = [run_one(name) for name in tool_names]
    return await asyncio.gather(*tasks, return_exceptions=True)


def _filter_valid_subdomains(subdomains: list[str], target: str = "") -> list[str]:
    """
    过滤无效的子域名
    - 去重
    - 过滤纯数字、明显无效的子域名
    - 过滤包含特殊字符、日期格式的子域名
    - 只保留与目标域名相关的子域名
    - 限制最大数量
    """
    import re

    seen = set()
    valid = []

    # 提取主域名（如 www.example.com -> example.com）
    target_domain = target.strip().lower()
    if target_domain.startswith("www."):
        target_domain = target_domain[4:]

    # 强过滤模式
    invalid_patterns = [
        re.compile(r'^(\d+\.)+\w+$'),           # 纯数字开头如 0.0.1.example.com
        re.compile(r'^[0-9-]+$'),                # 纯数字和横线
        re.compile(r'^\d+$'),                    # 纯数字
        re.compile(r'.*-{2,}.*'),                # 包含两个以上连续横线如 03----may
        re.compile(r'^\d{1,2}[-_]\d{1,2}$'),    # 日期格式开头如 03-24, 09-22
        re.compile(r'^\d{4}[-_]\w+$'),          # 如 0000-forbidden
        re.compile(r'[^a-z0-9\-\._]'),          # 包含非法字符（非字母数字、横线、点、下划线）
    ]

    for subdomain in subdomains:
        subdomain = subdomain.strip().lower()

        # 基础验证
        if not subdomain or len(subdomain) < 3:
            continue
        if subdomain in seen:
            continue
        if '.' not in subdomain:
            continue

        # 检查无效模式
        is_invalid = False
        for pattern in invalid_patterns:
            if pattern.match(subdomain):
                is_invalid = True
                break

        # 过滤明显无效的第一部分
        first_part = subdomain.split('.')[0]
        if not first_part:
            is_invalid = True
        elif first_part.isdigit():
            is_invalid = True
        elif len(first_part) <= 3 and first_part.isalnum() and not first_part.isalpha():
            # 短字符串且含数字如 012, 01a
            is_invalid = True
        elif len(first_part) > 40:
            # 过长的子域名前缀（可能是垃圾数据）
            is_invalid = True
        elif first_part.count('-') > 3 or first_part.count('_') > 3:
            # 包含过多分隔符
            is_invalid = True
        elif 'u003e' in subdomain or '%u' in subdomain or '%' in subdomain:
            # URL 编码残留如 u003e (>)
            is_invalid = True

        # 过滤与主域名不相关的域名
        if target_domain and not subdomain.endswith(target_domain):
            is_invalid = True

        # 过滤与目标完全相同的域名（不是子域名）
        if target_domain and subdomain == target_domain:
            is_invalid = True

        if is_invalid:
            continue

        seen.add(subdomain)
        valid.append(subdomain)

    # 限制最大数量（避免过多子域名导致扫描爆炸）
    MAX_SUBDOMAINS = 20
    if len(valid) > MAX_SUBDOMAINS:
        valid = valid[:MAX_SUBDOMAINS]

    return valid


def _fake_error_result(error_msg: str):
    """构造错误结果（兼容类型）"""
    from tools.result_model import ToolResult
    return ToolResult(success=False, error=error_msg, elapsed=0.0, target="", tool_name="")