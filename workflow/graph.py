# LangGraph 工作流图构建模块
# 构建核心图结构：条件分支、CDN 专属分支、节点串联与流转逻辑
# 完整流程：START -> plan -> [clarify_loop] -> passive -> active -> [cdn_bypass] -> analyze -> report -> END
from typing import Any

from langgraph.graph import StateGraph, START, END

from workflow.state import ReconState
from workflow.nodes.plan_node import plan_node
from workflow.nodes.passive_node import passive_node
from workflow.nodes.active_node import active_node
from workflow.nodes.reflect_node import reflect_node
from workflow.nodes.analyze_node import analyze_node
from workflow.nodes.report_node import report_node


# ==================== 条件路由函数 ====================

def route_after_plan(state: dict[str, Any]) -> str:
    """
    plan 节点后路由：
    - 如果需要澄清 -> 返回 end（由外部 main.py 对话循环处理）
    - 如果是退出 -> 返回 end
    - 如果是闲聊 -> 返回 end（但会在状态中标记）
    - 如果扫描范围是 passive -> 到 passive
    - 如果扫描范围是 active 且任务列表只有主动工具 -> 跳过 passive 直接到 active
    - 正常扫描 -> 继续到 passive
    """
    if state.get("should_exit"):
        return "end"
    if state.get("clarification_needed"):
        return "end"
    if state.get("intent") == "chat":
        return "end"
    
    scope = state.get("scan_scope", "full")
    task_list = state.get("task_list", [])
    
    ACTIVE_TOOLS = {"cdn_detect", "cdn_bypass", "portscan", "http_fingerprint", "dir_scan", "api_discover", "screenshot"}
    
    if scope == "passive":
        return "passive"
    
    if scope == "active" and task_list:
        if all(t in ACTIVE_TOOLS for t in task_list):
            return "active"
    
    return "passive"


def route_after_passive(state: dict[str, Any]) -> str:
    """
    passive 节点后路由：
    - 如果扫描范围是 passive -> 直接到 report
    - 否则继续到 active
    """
    scope = state.get("scan_scope", "full")
    if scope == "passive":
        return "analyze"
    return "active"


def route_after_active(state: dict[str, Any]) -> str:
    """
    active 节点后路由：
    - 如果检测到 CDN -> 先执行 cdn_bypass
    - 否则直接到 analyze
    """
    if state.get("has_cdn") and not state.get("real_ip"):
        return "cdn_bypass"
    return "analyze"


def route_after_reflect(state: dict[str, Any]) -> str:
    """
    reflect 节点后路由：
    - 如果发现了新资产 -> 回到 plan 继续迭代
    - 否则 -> 到 analyze
    """
    if state.get("new_asset_found") and state.get("iteration", 0) < state.get("max_iterations", 30):
        return "plan"
    return "analyze"


def route_after_analyze(state: dict[str, Any]) -> str:
    """
    analyze 节点后路由：
    - 如果扫描范围是 full -> 到 report
    - 如果扫描范围是 active -> 到 report
    - 否则到 end
    """
    scope = state.get("scan_scope", "full")
    if scope in ("full", "active"):
        return "report"
    return "end"


def cdn_bypass_node(state: dict[str, Any]) -> dict[str, Any]:
    """CDN 绕过节点：调用 cdn_bypass 工具获取真实 IP"""
    import asyncio
    from tools.registry import get_tool

    target = state.get("target", "")
    tool = get_tool("cdn_bypass")
    if tool:
        result = asyncio.run(tool.execute(target))
        if result.success and result.data:
            return {
                "real_ip": result.data.get("real_ip", ""),
                "ips": result.data.get("candidate_ips", []),
                "messages": [f"[cdn_bypass] 发现候选真实 IP: {result.data.get('candidate_ips', [])}"],
            }
    return {"messages": ["[cdn_bypass] 未获取到真实 IP"]}


# ==================== 图构建 ====================

def build_full_graph() -> StateGraph:
    """
    构建完整智能工作流图

    START -> plan -> [passive -> active -> cdn_bypass -> reflect] -> analyze -> report -> END
    支持：
    - 澄清循环（plan -> clarify -> plan）
    - 迭代循环（reflect -> plan）
    - CDN 分支（active -> cdn_bypass -> analyze）
    - 错误处理（全局 error_handler）
    """
    graph = StateGraph(ReconState)

    # 注册节点
    graph.add_node("plan", plan_node) # 计划节点
    graph.add_node("passive", passive_node) # 被动扫描节点
    graph.add_node("active", active_node) # 主动扫描节点
    graph.add_node("cdn_bypass", cdn_bypass_node) # CDN 绕过节点
    graph.add_node("reflect", reflect_node) # 反射节点
    graph.add_node("analyze", analyze_node) # 分析节点
    graph.add_node("report", report_node)   # 报告节点
    # error_handler 节点已注册但当前通过条件路由控制，
    # 如需全局错误处理可在各节点内部捕获

    # 起始边
    graph.add_edge(START, "plan")

    # plan 后条件分支
    graph.add_conditional_edges(
        "plan",
        route_after_plan,
        {
            "passive": "passive",
            "active": "active",
            "end": END,
        },
    )

    # passive 后条件分支
    graph.add_conditional_edges(
        "passive",
        route_after_passive,
        {
            "active": "active",
            "analyze": "analyze",
        },
    )

    # active 后条件分支
    graph.add_conditional_edges(
        "active",
        route_after_active,
        {
            "cdn_bypass": "cdn_bypass",
            "analyze": "analyze",
        },
    )

    # cdn_bypass -> reflect
    graph.add_edge("cdn_bypass", "reflect")

    # reflect 后条件分支（迭代循环）
    graph.add_conditional_edges(
        "reflect",
        route_after_reflect,
        {
            "plan": "plan",
            "analyze": "analyze",
        },
    )

    # analyze 后条件分支
    graph.add_conditional_edges(
        "analyze",
        route_after_analyze,
        {
            "report": "report",
            "end": END,
        },
    )

    # report -> END
    graph.add_edge("report", END)

    return graph


def compile_graph():
    """编译工作流图"""
    graph = build_full_graph()
    return graph.compile()
