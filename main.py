# CLI 命令行入口文件
# 支持参数启动：单目标扫描、指定阶段、批量配置文件启动
# 支持对话式交互：Agent 分析用户意图、主动澄清提问、自动规划扫描任务
# 启动前自动调用 startup_check 进行环境自检

import argparse
import asyncio
import sys
from datetime import datetime
from pathlib import Path

# 确保项目根目录在 Python 路径中
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from utils.startup_check import run_startup_check
from utils.cache_helper import clear_all_cache
from utils.validators import detect_target_type, sanitize_target
from workflow.graph import compile_graph


def print_banner():
    """输出欢迎横幅"""
    print("=" * 60)
    print("  AI 渗透测试信息收集 Agent")
    print("  智能规划 · 并发执行 · 自我反思")
    print("=" * 60)
    print()
    print("  支持自然语言对话，例如：")
    print('    "帮我扫描一下 example.com"')
    print('    "对 scanme.nmap.org 做端口扫描"')
    print('    "查看之前的扫描报告"')
    print()
    print("  快捷命令：")
    print("    /help   - 显示帮助")
    print("    /tools  - 列出可用工具")
    print("    /check  - 一键检查环境")
    print("    /clear  - 清空对话历史")
    print("    /fresh  - 清空缓存并强制重新扫描")
    print("    /exit   - 退出程序")
    print("=" * 60)
    print()


def print_help():
    """输出帮助信息"""
    print("""
【AI Recon Agent 帮助】

对话指令：
  /help          显示此帮助
  /tools         列出所有可用扫描工具
  /check         一键检查环境（依赖、工具、网络等）
  /clear         清空当前对话历史
  /fresh         清空缓存并强制重新扫描（跳过缓存）
  /exit 或 /quit 退出程序

使用示例：
  帮我扫描 example.com
  对 192.168.1.1 做全端口扫描
  只收集 example.com 的被动信息
  查看报告

Agent 会自动分析您的需求，如有不明确之处会主动提问。
""")


def print_tools():
    """输出可用工具列表"""
    from tools.registry import list_tools, get_passive_tools, get_active_tools

    print("\n【可用工具列表】")
    print("\n被动信息收集（无流量到达目标）：")
    for t in get_passive_tools():
        print(f"  - {t}")
    print("\n主动扫描（直接探测目标）：")
    for t in get_active_tools():
        print(f"  - {t}")
    print()


def print_scan_summary(state: dict) -> None:
    """输出扫描结果摘要（展示所有发现的资产）"""
    print("\n" + "-" * 60)
    print("【扫描结果摘要】")
    print("-" * 60)

    target = state.get("target", "N/A")
    phase = state.get("current_phase", "unknown")
    completed = state.get("completed_tasks", [])

    print(f"目标: {target}")
    print(f"最终阶段: {phase}")
    print(f"已完成任务: {', '.join(completed) if completed else '无'}")

    # 提示缓存命中
    from_cache_tasks = [t for t in completed if "@cached" in t]
    if from_cache_tasks:
        print(f"\n⚡ 缓存命中 ({len(from_cache_tasks)} 个): {'、'.join(from_cache_tasks)}")
        print("   （如需重新扫描，请使用 /fresh 命令或 /clear 清理缓存）")

    # ===== 敏感目录爆破结果 =====
    sensitive_paths = state.get("sensitive_paths", [])
    if sensitive_paths:
        print(f"\n🗂️  敏感目录爆破 ({len(sensitive_paths)} 个):")
        for p in sensitive_paths[:10]:
            path = p.get("path", p.get("url", "未知"))
            status = p.get("status", p.get("status_code", "?"))
            length = p.get("length", p.get("size", "?"))
            print(f"  - {path} | 状态码: {status} | 大小: {length}")
        if len(sensitive_paths) > 10:
            print(f"  ... 共 {len(sensitive_paths)} 个")

    # ===== 子域名 =====
    subdomains = state.get("subdomains", [])
    if subdomains:
        print(f"\n🌐 子域名 ({len(subdomains)} 个):")
        for s in subdomains[:5]:
            print(f"  - {s}")
        if len(subdomains) > 5:
            print(f"  ... 共 {len(subdomains)} 个")

    # ===== 开放端口 =====
    open_ports = state.get("open_ports", [])
    if open_ports:
        print(f"\n🔌 开放端口 ({len(open_ports)} 个):")
        for p in open_ports[:5]:
            print(f"  - {p.get('ip', '?')}:{p.get('port', '?')} {p.get('service', '')}")
        if len(open_ports) > 5:
            print(f"  ... 共 {len(open_ports)} 个")

    # ===== Web 指纹 =====
    fingerprints = state.get("fingerprints", [])
    if fingerprints:
        print(f"\n🔍 Web 指纹 ({len(fingerprints)} 个):")
        for f in fingerprints[:5]:
            print(f"  - {f.get('name', '?')} {f.get('version', '')}")

    # ===== API 接口 =====
    apis = state.get("apis", [])
    if apis:
        print(f"\n🔗 API 接口 ({len(apis)} 个):")
        for a in apis[:5]:
            print(f"  - {a.get('endpoint', '?')} [{a.get('method', 'GET')}]")
        if len(apis) > 5:
            print(f"  ... 共 {len(apis)} 个")

    # ===== CDN/WAF =====
    has_cdn = state.get("has_cdn", False)
    has_waf = state.get("has_waf", False)
    if has_cdn or has_waf:
        print(f"\n🛡️  CDN/WAF:")
        print(f"  - CDN: {'已识别' if has_cdn else '未识别'}")
        print(f"  - WAF: {'已识别' if has_waf else '未识别'}")

    # ===== WHOIS =====
    whois_info = state.get("whois_info", {})
    if whois_info:
        print(f"\n📋 WHOIS 信息:")
        for k, v in list(whois_info.items())[:5]:
            print(f"  - {k}: {v}")

    # ===== DNS 记录 =====
    dns_records = state.get("dns_records", [])
    if dns_records:
        print(f"\n📡 DNS 记录 ({len(dns_records)} 条):")
        # 兼容两种格式：
        # 1. list[dict] 格式: [{"type": "A", "name": "x.com", "value": "1.2.3.4"}, ...]
        # 2. dict[str, list[str]] 格式: {"A": ["1.2.3.4"], "MX": ["mail.x.com"], ...}
        if isinstance(dns_records, dict):
            count = 0
            for rtype, values in dns_records.items():
                if count >= 5:
                    break
                if isinstance(values, list):
                    for val in values:
                        if count >= 5:
                            break
                        print(f"  - {rtype}: {val}")
                        count += 1
                else:
                    print(f"  - {rtype}: {values}")
                    count += 1
        elif isinstance(dns_records, list):
            for r in dns_records[:5]:
                print(f"  - {r.get('type', '?')}: {r.get('value', '?')}")

    # ===== 漏洞提示 =====
    vuln_hints = state.get("vuln_hints", [])
    if vuln_hints:
        print(f"\n⚠️  风险提示 ({len(vuln_hints)} 个):")
        for v in vuln_hints[:5]:
            print(f"  - [{v.get('severity', '?')}] {v.get('cve', '')} {v.get('description', '')}")

    # ===== 截图 =====
    screenshots = state.get("screenshots", [])
    if screenshots:
        print(f"\n📸 页面截图 ({len(screenshots)} 张):")
        for s in screenshots[:3]:
            print(f"  - {s.get('target', '?')}: {s.get('path', '?')}")

    # ===== 报告文件 =====
    messages = state.get("messages", [])
    report_msgs = [m for m in messages if "[report]" in m and "输出路径" in m]
    if report_msgs:
        print(f"\n📄 {report_msgs[-1]}")

    # ===== 错误 =====
    errors = state.get("errors", [])
    if errors:
        print(f"\n❌ 错误 ({len(errors)} 个):")
        for e in errors[:3]:
            print(f"  ! {e}")

    # 没有任何发现时提示
    has_any_result = any([
        sensitive_paths, subdomains, open_ports, fingerprints,
        apis, whois_info, dns_records, vuln_hints, screenshots,
    ])
    if not has_any_result and not errors:
        print("\n💡 本次扫描未发现资产（可能目标无响应或工具未成功执行）")

    print("-" * 60)


async def run_conversation_mode():
    """对话模式主循环"""
    print_banner()

    # 环境自检
    if not run_startup_check(strict=False):
        print("[警告] 启动检查未完全通过，部分功能可能受限\n")

    # 编译工作流图
    app = compile_graph()

    # 对话状态
    conversation_history = []
    current_state = {}
    skip_cache = False  # /fresh 命令控制：下一次扫描跳过缓存

    while True:
        try:
            user_input = input("\n用户: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n再见！")
            break

        if not user_input:
            continue

        # 处理快捷命令
        if user_input.startswith("/"):
            # 按空格分割：命令名 + 可能的后续参数
            parts = user_input.split(maxsplit=1)
            cmd = parts[0].lower()
            cmd_arg = parts[1].strip() if len(parts) > 1 else ""

            # /fresh 支持与扫描请求组合使用：先清缓存，再处理剩余部分
            if cmd == "/fresh":
                from utils.cache_helper import clear_all_cache
                clear_all_cache()
                skip_cache = True
                if cmd_arg:
                    # 带参数：清缓存后继续处理剩余部分作为扫描请求
                    print("Agent: 已清空所有缓存，本次扫描将强制跳过缓存")
                    user_input = cmd_arg  # 覆盖为剩余部分，继续走正常扫描流程
                else:
                    # 不带参数：仅清缓存
                    print("Agent: 已清空所有缓存，下一次扫描将强制跳过缓存")
                    continue
            elif cmd in ("/exit", "/quit", "/bye"):
                print("Agent: 再见！扫描报告已保存到 data/reports/")
                break
            elif cmd == "/help":
                print_help()
                continue
            elif cmd == "/tools":
                print_tools()
                continue
            elif cmd == "/clear":
                conversation_history.clear()
                current_state = {}
                from utils.cache_helper import clear_all_cache
                clear_all_cache()
                skip_cache = False
                print("Agent: 对话历史和扫描缓存已清空")
                continue
            elif cmd == "/check":
                print("\nAgent: 正在执行环境检查...")
                import subprocess
                subprocess.run(["python", str(ROOT_DIR / "check_env.py")], cwd=str(ROOT_DIR))
                continue
            else:
                print(f"Agent: 未知命令 '{cmd}'，输入 /help 查看帮助")
                continue

        # 如果 skip_cache=True，在工作流开始前清除所有缓存
        if skip_cache:
            clear_all_cache()
            print("Agent: ⚡ 已强制清除所有缓存，本次扫描将跳过缓存")

        # 构建输入状态
        input_state = {
            "user_input": user_input,
            "conversation_history": conversation_history,
            "target": current_state.get("target", ""),
            "target_type": current_state.get("target_type", ""),
            "scan_scope": current_state.get("scan_scope", "full"),
            "iteration": current_state.get("iteration", 0),
            "max_iterations": current_state.get("max_iterations", 5),
            "discovered_assets": current_state.get("discovered_assets", []),
            "skip_cache": skip_cache,  # /fresh 控制位
        }
        skip_cache = False  # 一次性 flag，用完即清

        # 如果之前有目标且用户没有指定新目标，保留旧目标
        #（plan_node 会处理这个逻辑）

        print("Agent: 正在分析您的需求...")

        try:
            # 执行工作流
            result = await app.ainvoke(input_state)
        except Exception as e:
            print(f"Agent: 执行出错: {e}")
            continue

        # 更新对话历史
        conversation_history = result.get("conversation_history", conversation_history)
        current_state = result

        # 处理需要澄清的情况
        if result.get("clarification_needed"):
            question = result.get("pending_question", "请提供更多信息")
            print(f"Agent: {question}")
            continue

        # 处理退出意图
        if result.get("should_exit"):
            print("Agent: 再见！")
            break

        # 处理闲聊（无扫描任务）
        task_list = result.get("task_list", [])
        if not task_list and result.get("current_phase") == "plan":
            # 检查 agent 回复
            msgs = result.get("messages", [])
            if msgs:
                print(f"Agent: {msgs[-1]}")
            continue

        # 扫描完成，输出摘要
        print_scan_summary(result)
        print("\nAgent: 扫描已完成。您可以继续输入新目标或输入 /help 查看帮助。")


async def run_direct_scan(target: str, scope: str = "full"):
    """直接扫描模式（非对话）"""
    print(f"【直接扫描模式】目标: {target}, 范围: {scope}")

    app = compile_graph()

    input_state = {
        "user_input": f"扫描 {target}",
        "target": sanitize_target(target),
        "target_type": detect_target_type(target),
        "scan_scope": scope,
        "conversation_history": [],
    }

    result = await app.ainvoke(input_state)
    print_scan_summary(result)


def main():
    """CLI 入口"""
    parser = argparse.ArgumentParser(
        description="AI 渗透测试信息收集 Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py                          # 启动对话模式
  python main.py -t example.com           # 直接扫描目标
  python main.py -t example.com -s passive # 仅被动扫描
        """,
    )
    parser.add_argument("-t", "--target", help="直接扫描目标（跳过对话）")
    parser.add_argument(
        "-s", "--scope",
        choices=["full", "passive", "active"],
        default="full",
        help="扫描范围 (默认: full)",
    )
    parser.add_argument("--no-check", action="store_true", help="跳过启动自检")

    args = parser.parse_args()

    # 启动自检
    if not args.no_check:
        try:
            run_startup_check(strict=False)
        except Exception:
            pass

    if args.target:
        # 直接扫描模式
        asyncio.run(run_direct_scan(args.target, args.scope))
    else:
        # 对话模式
        asyncio.run(run_conversation_mode())


if __name__ == "__main__":
    main()
