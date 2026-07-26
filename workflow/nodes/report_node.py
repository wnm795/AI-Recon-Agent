# 报告生成节点
# 整合全量资产、漏洞、泄露、防护信息，输出 Markdown/JSON/CSV 多格式报告

import asyncio
from typing import Any

from tools.analysis.report_tool import ReportTool


def report_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    报告生成节点：调用 ReportTool 生成扫描报告
    """
    target = state.get("target", "")

    report_tool = ReportTool()
    result = asyncio.run(report_tool.execute(target, params={"state": state}))

    messages = [f"[report] 报告生成完成: {result.success}"]

    if result.success and result.data:
        messages.append(f"[report] 输出路径: {result.data.get('output_path', 'N/A')}")
    else:
        messages.append(f"[report] 报告生成失败: {result.error}")

    return {
        "current_phase": "report",
        "completed_tasks": ["report"],
        "messages": messages,
    }
