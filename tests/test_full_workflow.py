# 全流程集成测试
# 验证 LangGraph 工作流：whois -> subdomain -> portscan -> report

import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from utils.cache_helper import clear_all_cache
from workflow.graph import compile_graph


async def _run_full_workflow():
    """
    全流程验证核心逻辑
    """
    # 清理缓存
    clear_all_cache()

    # 编译工作流图
    app = compile_graph()

    # 执行全流程（异步 API）
    result = await app.ainvoke({
        "target": "scanme.nmap.org",
        "user_input": "帮我扫描 scanme.nmap.org",
        "scan_scope": "full",
    })
    return result


def test_full_workflow():
    """
    全流程验证：graph.ainvoke({"target": "example.com"})
    检查 State 中是否填充了数据，并生成报告
    """
    result = asyncio.run(_run_full_workflow())

    # 验证状态数据
    print("\n" + "=" * 60)
    print("扫描结果摘要")
    print("=" * 60)

    # 基本字段
    assert result.get("target") == "scanme.nmap.org", "目标应为 scanme.nmap.org"
    print(f"[OK] 目标: {result.get('target')}")

    assert result.get("current_phase") == "report", f"最终阶段应为 report, 实际: {result.get('current_phase')}"
    print(f"[OK] 最终阶段: {result.get('current_phase')}")

    # 已完成任务
    completed = result.get("completed_tasks", [])
    print(f"[OK] 已完成任务: {completed}")
    assert "whois" in completed, "whois 应已完成"
    assert "subdomain" in completed, "subdomain 应已完成"
    assert "report" in completed, "report 应已完成"

    # 子域名
    subdomains = result.get("subdomains", [])
    print(f"[OK] 子域名数量: {len(subdomains)}")
    if subdomains:
        for sub in subdomains[:5]:
            print(f"       {sub}")
        if len(subdomains) > 5:
            print(f"       ... 共 {len(subdomains)} 个")

    # 开放端口
    open_ports = result.get("open_ports", [])
    print(f"[OK] 开放端口数量: {len(open_ports)}")
    if open_ports:
        for port in open_ports:
            print(f"       {port.get('ip', '?')}:{port.get('port', '?')} {port.get('service', '')}")

    # IP 地址
    ips = result.get("ips", [])
    print(f"[OK] IP 地址: {ips}")

    # 错误
    errors = result.get("errors", [])
    print(f"[INFO] 错误数: {len(errors)}")
    for err in errors:
        print(f"       {err}")

    # 消息
    messages = result.get("messages", [])
    print(f"[OK] 消息数: {len(messages)}")
    for msg in messages:
        print(f"       {msg}")

    # 验证报告生成
    report_msgs = [m for m in messages if "[report]" in m]
    assert len(report_msgs) > 0, "应有报告生成消息"
    print(f"\n[OK] 报告消息: {report_msgs}")

    print("=" * 60)
    print("全流程验证通过!")
    print("=" * 60)

    return result


if __name__ == "__main__":
    result = asyncio.run(_run_full_workflow())