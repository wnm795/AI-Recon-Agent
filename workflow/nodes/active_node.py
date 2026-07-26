# 主动工具多资产并行扫描节点
# 识别未扫描子域名/IP，使用 asyncio.gather 为每个资产创建独立并发分支

import asyncio
import re
from typing import Any

from config.settings import MAX_CONCURRENT_ASSETS
from tools.registry import get_tool

IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')


def is_valid_ip(address: str) -> bool:
    return bool(IP_PATTERN.match(address))


# 主动工具白名单
ACTIVE_TOOLS = {
    "cdn_detect", "cdn_bypass", "portscan",
    "http_fingerprint", "dir_scan", "api_discover", "screenshot",
}


def active_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    并发执行主动扫描工具

    对主目标 + 已发现的子域名分别执行主动工具
    """
    target = state.get("target", "")
    task_list = state.get("task_list", [])
    subdomains = state.get("subdomains", [])
    skip_cache = state.get("skip_cache", False)

    # 筛选主动工具
    active_tasks = [t for t in task_list if t in ACTIVE_TOOLS]

    if not active_tasks or not target:
        return {
            "current_phase": "active",
            "completed_tasks": [],  # 明确返回空列表
            "messages": ["[active] 无主动工具或目标，跳过"],
            "skip_cache": skip_cache,
        }

    # 构建扫描目标列表：主目标 + 子域名
    targets_to_scan = [target]
    if subdomains:
        # 取前 10 个子域名避免过多
        targets_to_scan.extend(subdomains[:10])
        targets_to_scan = list(dict.fromkeys(targets_to_scan))

    # 执行主动扫描
    results = asyncio.run(_run_active_scans(targets_to_scan, active_tasks, skip_cache))

    # 收集结果
    all_ports = []
    all_fingerprints = []
    all_paths = []
    all_apis = []
    all_screenshots = []
    all_ips = set(state.get("ips", []))
    completed = []
    errors = []
    messages = []
    has_cdn = False
    has_waf = False
    real_ip = ""

    for scan_target, tool_name, result in results:
        if result.success and result.data:
            completed.append(f"{tool_name}:{scan_target}")
            messages.append(f"[active] {tool_name}@{scan_target} 成功")

            data = result.data
            if "open_ports" in data:
                all_ports.extend(data["open_ports"])
            if "fingerprints" in data:
                all_fingerprints.extend(data["fingerprints"])
            if "sensitive_paths" in data:
                all_paths.extend(data["sensitive_paths"])
            if "apis" in data:
                all_apis.extend(data["apis"])
            if "screenshot_path" in data and data["screenshot_path"]:
                all_screenshots.append({
                    "target": scan_target,
                    "path": data["screenshot_path"],
                })
            if "host" in data and data["host"] and is_valid_ip(data["host"]):
                all_ips.add(data["host"])
            if tool_name == "cdn_detect":
                if data.get("has_cdn"):
                    has_cdn = True
                if data.get("has_waf"):
                    has_waf = True
            if tool_name == "cdn_bypass" and data.get("real_ip"):
                real_ip = data["real_ip"]
        else:
            errors.append(f"{tool_name}@{scan_target}: {result.error}")

    updates: dict[str, Any] = {
        "current_phase": "active",
        "completed_tasks": completed,
        "messages": messages,
        "open_ports": all_ports,
        "fingerprints": all_fingerprints,
        "sensitive_paths": all_paths,
        "apis": all_apis,
        "screenshots": all_screenshots,
        "ips": list(all_ips),
        "has_cdn": has_cdn,
        "has_waf": has_waf,
        "skip_cache": skip_cache,
    }

    if real_ip:
        updates["real_ip"] = real_ip
    if errors:
        updates["errors"] = errors

    return updates


async def _run_active_scans(targets: list[str], tool_names: list[str], skip_cache: bool = False) -> list[tuple[str, str, Any]]:
    """
    并发执行主动扫描
    返回 [(target, tool_name, ToolResult), ...]
    """
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_ASSETS)

    async def run_one(target: str, tool_name: str):
        async with semaphore:
            tool = get_tool(tool_name)
            if not tool:
                from tools.result_model import ToolResult
                return target, tool_name, ToolResult(
                    success=False, error=f"工具 {tool_name} 未注册",
                    elapsed=0.0, target=target, tool_name=tool_name,
                )
            result = await tool.execute(target, params={"skip_cache": skip_cache})
            return target, tool_name, result

    tasks = []
    for target in list(targets):
        for tool_name in list(tool_names):
            tasks.append(run_one(target, tool_name))

    # gather 后过滤掉 Exception 实例，将其转为 ToolResult 写入 errors，
    # 避免上游因结果类型不一致导致 AttributeError 而静默失败
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)
    clean_results: list[tuple[str, str, Any]] = []
    for item in raw_results:
        if isinstance(item, BaseException):
            # run_one 内部已经捕获异常，正常不应到达这里
            # 仅作为兜底：未捕获的异常转为错误结果
            from tools.result_model import ToolResult
            clean_results.append((
                "", "", ToolResult(
                    success=False,
                    error=f"未捕获异常: {type(item).__name__}: {item}",
                    elapsed=0.0, target="", tool_name="",
                )
            ))
        else:
            clean_results.append(item)
    return clean_results
