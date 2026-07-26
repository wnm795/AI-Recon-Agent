# LLM 动态任务规划节点
# 读取当前状态资产、对话历史，LLM 输出阶段+任务列表
# 支持意图分析、澄清提问、动态任务规划
# LLM 调用失败时自动降级基础扫描任务模板
# 内置规则引擎：在 LLM 不可用或输出不合规时，能基于中文关键词精准匹配单工具请求

import json
import re
from datetime import datetime
from typing import Any

from config.prompts import INTENT_ANALYSIS_PROMPT, FALLBACK_TASK_PLAN
from config.settings import (
    VERIFY_API_BASE, PLANNER_API_KEY, PLANNER_MODEL,
)
from tools.registry import list_tools


# ==================== 内置规则引擎：中文关键词 -> 工具映射 ====================

# 关键词 -> 工具的精确映射表（顺序敏感，前面的优先匹配）
KEYWORD_TOOL_RULES = [
    # 目录爆破
    (re.compile(r'(爆破|扫描|枚举|遍历|探测).*?(目录|路径|文件|字典)', re.I), "dir_scan"),
    (re.compile(r'dir[_-]?scan|目录扫描|敏感目录', re.I), "dir_scan"),
    # 端口扫描
    (re.compile(r'(扫|扫描|探测).*?(端口|port)', re.I), "portscan"),
    (re.compile(r'port[_-]?scan|端口扫描|nmap', re.I), "portscan"),
    # 子域名
    (re.compile(r'(扫|扫描|挖掘|发现|枚举).*?子域名', re.I), "subdomain"),
    (re.compile(r'subdomain|子域名', re.I), "subdomain"),
    # WHOIS
    (re.compile(r'whois|注册人|注册信息|域名注册', re.I), "whois"),
    # 指纹
    (re.compile(r'(web)?指纹|识别.*?技术栈|http.*?指纹', re.I), "http_fingerprint"),
    # CDN/WAF
    (re.compile(r'cdn|waf|内容分发|防火墙', re.I), "cdn_detect"),
    # 真实IP
    (re.compile(r'真实\s?ip|绕过\s?cdn|cdn\s?穿透|真实地址', re.I), "cdn_bypass"),
    # API
    (re.compile(r'api\s?(接口|发现|提取)|接口\s?发现|js\s?接口', re.I), "api_discover"),
    # 截图
    (re.compile(r'截图|截屏|页面截图|screenshot', re.I), "screenshot"),
    # 漏洞
    (re.compile(r'漏洞|cve|风险匹配|漏洞匹配', re.I), "vuln_match"),
    # 备案
    (re.compile(r'备案|icp|公司备案', re.I), "icp"),
    # 代码泄露
    (re.compile(r'代码泄露|github\s?泄露|github\s?泄漏|代码泄漏', re.I), "github_leak"),
    # 历史归档
    (re.compile(r'历史|归档|wayback|时光机', re.I), "wayback"),
    # DNS
    (re.compile(r'dns|域名解析|ns记录|mx记录', re.I), "dns_enum"),
    # 证书
    (re.compile(r'证书|证书透明度|cert\s?log|crt\.sh', re.I), "cert_log"),
]

# 全面/全扫描关键词
FULL_SCOPE_KEYWORDS = re.compile(r'(全面|完整|全部|全盘|所有|整个).*?扫描|全面测试|完整测试|整体测试')

# 主动扫描关键词
ACTIVE_SCOPE_KEYWORDS = re.compile(r'(主动|爆破|扫|扫描|探测|枚举).*?$|^(主动|爆破|扫|扫描|探测|枚举)')

# 被动扫描关键词
PASSIVE_SCOPE_KEYWORDS = re.compile(r'(被动|只收集|仅收集|不接触目标)')


def _rule_based_understand(user_input: str) -> dict[str, Any] | None:
    """
    基于规则的意图理解（LLM 不可用时的降级方案）

    处理场景：
    - 用户明确指定单一工具时（如"爆破目录"），直接返回对应 task_list
    - 用户说"全面扫描"时，返回完整任务链
    - 用户说"被动/主动"时，正确选择 scan_scope

    Returns:
        dict: 包含 intent, target, scan_scope, task_list 的字典；如果无法理解返回 None
    """
    if not user_input or not user_input.strip():
        return None

    text = user_input.strip()

    # 1. 提取 target
    target = _extract_target_from_input(text)
    if not target:
        return None

    # 2. 判断 scan_scope
    if FULL_SCOPE_KEYWORDS.search(text):
        scan_scope = "full"
        matched_tool = None
    elif PASSIVE_SCOPE_KEYWORDS.search(text):
        scan_scope = "passive"
        matched_tool = None
    elif ACTIVE_SCOPE_KEYWORDS.search(text):
        scan_scope = "active"
        matched_tool = None
    else:
        scan_scope = "active"
        matched_tool = None

    # 3. 匹配多工具关键词（收集所有匹配的工具，支持用户同时指定多个操作）
    matched_tools = []
    if scan_scope != "full":
        for pattern, tool in KEYWORD_TOOL_RULES:
            if pattern.search(text):
                if tool not in matched_tools:
                    matched_tools.append(tool)

    # 4. 构建 task_list（report 工具由 report_node 节点执行，不加入 task_list 避免重复调用）
    if matched_tools:
        task_list = matched_tools
    elif scan_scope == "passive":
        task_list = ["whois", "subdomain", "cert_log"]
    elif scan_scope == "active":
        task_list = ["portscan", "http_fingerprint", "dir_scan"]
    else:  # full
        task_list = [
            "whois", "dns_enum", "subdomain", "cert_log",
            "cdn_detect", "portscan", "http_fingerprint", "dir_scan",
        ]

    # 5. 校验工具是否存在
    valid_tools = set(list_tools())
    task_list = [t for t in task_list if t in valid_tools]

    return {
        "intent": "scan",
        "reasoning": f"规则引擎匹配: target={target}, scope={scan_scope}, tools={matched_tools}",
        "target": target,
        "target_type": _guess_target_type(target),
        "scan_scope": scan_scope,
        "task_list": task_list,
        "tool_params": {},
        "pending_question": "",
        "clarification_needed": False,
        "response_to_user": f"好的，正在对 {target} 执行扫描...",
    }


def _guess_target_type(target: str) -> str:
    """判断 target 类型"""
    if target.startswith(("http://", "https://")):
        return "url"
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', target):
        return "ip"
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', target):
        return "domain"
    return "unknown"


def _sanitize_target(target: str) -> str:
    """
    清洗 target：去除中文、标点、解释性后缀
    复用 dir_scan 工具的提取逻辑，保证一致性
    """
    if not target:
        return ""

    try:
        from tools.active.dir_scan_tool import extract_clean_url
        cleaned = extract_clean_url(target)
        if cleaned:
            return cleaned
    except ImportError:
        pass

    # 降级方案
    text = str(target).strip()
    https_match = re.search(r'https?://[^\s\x00-\x1f\x7f`"\'<>\\^|,;]*', text, re.IGNORECASE)
    if https_match:
        return re.sub(r'[`"\'<>\\^|{}\s,;]+$', '', https_match.group(0))
    domain_match = re.search(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b(?::\d{1,5})?',
        text
    )
    if domain_match:
        return domain_match.group(0)
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b(?::\d{1,5})?', text)
    if ip_match:
        return ip_match.group(0)
    return ""


def _get_llm_client():
    """获取 LLM 客户端（使用 Finna 代理服务）"""
    if PLANNER_API_KEY and VERIFY_API_BASE:
        try:
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=PLANNER_MODEL,
                api_key=PLANNER_API_KEY,
                base_url=VERIFY_API_BASE,
                temperature=0.2,
            )
        except ImportError:
            pass

    return None


def _format_conversation_history(history: list[dict]) -> str:
    """格式化对话历史为字符串"""
    if not history:
        return "（无对话历史）"
    lines = []
    for entry in history[-10:]:  # 只取最近 10 轮
        role = entry.get("role", "unknown")
        content = entry.get("content", "")
        ts = entry.get("timestamp", "")
        lines.append(f"[{role}] ({ts}): {content}")
    return "\n".join(lines)


def _format_assets(state: dict) -> str:
    """格式化当前已发现资产"""
    parts = []
    subdomains = state.get("subdomains", [])
    ips = state.get("ips", [])
    ports = state.get("open_ports", [])
    fingerprints = state.get("fingerprints", [])

    if subdomains:
        parts.append(f"子域名: {subdomains[:5]}..." if len(subdomains) > 5 else f"子域名: {subdomains}")
    if ips:
        parts.append(f"IP: {ips}")
    if ports:
        parts.append(f"开放端口: {len(ports)} 个")
    if fingerprints:
        parts.append(f"指纹: {len(fingerprints)} 个")

    return "\n".join(parts) if parts else "（暂无已发现资产）"


def _parse_llm_response(content: str) -> dict:
    """解析 LLM 返回的 JSON 字符串"""
    # 尝试提取 JSON 内容（去除可能的 markdown 代码块）
    content = content.strip()
    if content.startswith("```"):
        # 去除 markdown 代码块
        lines = content.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        content = "\n".join(lines).strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # 尝试从文本中提取 JSON
        start = content.find("{")
        end = content.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(content[start:end+1])
            except json.JSONDecodeError:
                pass
        raise ValueError(f"无法解析 LLM 响应为 JSON: {content[:200]}")


def _build_task_list_from_intent(parsed: dict, state: dict) -> list[str]:
    """根据意图解析结果构建任务列表"""
    intent = parsed.get("intent", "scan")
    scope = parsed.get("scan_scope", "full")
    custom_tasks = parsed.get("task_list", [])

    if intent != "scan":
        return []

    if custom_tasks:
        # 过滤掉注册表中不存在的工具
        valid_tools = set(list_tools())
        return [t for t in custom_tasks if t in valid_tools]

    # 使用默认模板（report 工具由 report_node 节点执行，不在 task_list 中）
    if scope == "passive":
        return ["whois", "dns_enum", "subdomain", "cert_log", "wayback"]
    elif scope == "active":
        return ["cdn_detect", "portscan", "http_fingerprint", "dir_scan"]
    else:
        return ["whois", "subdomain", "portscan", "http_fingerprint"]


def plan_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    LLM 动态任务规划节点（同步版本，供 LangGraph 调用）

    分析用户输入意图，决定：
    1. 是否需要澄清（信息不足时主动提问）
    2. 扫描目标和范围
    3. 具体要执行的工具列表和参数
    """
    user_input = state.get("user_input", "").strip()
    conversation_history = state.get("conversation_history", [])

    # 将当前输入加入对话历史
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conversation_history.append({
        "role": "user",
        "content": user_input,
        "timestamp": now,
    })

    # 如果没有用户输入，返回等待状态
    if not user_input:
        return {
            "intent": "clarify",
            "conversation_history": conversation_history,
            "pending_question": "请输入您要扫描的目标或需求描述",
            "clarification_needed": True,
            "current_phase": "plan",
            "messages": ["[plan] 等待用户输入..."],
        }

    # 闲聊/退出关键词快速匹配（避免不必要的 LLM 调用）
    text_lower = user_input.lower().strip()
    
    # 闲聊关键词（模糊匹配）
    chat_keywords = ["你好", "hi", "hello", "在吗", "您好", "你是谁", "请问你是", "什么是", "介绍一下", "功能", "能力"]
    if any(keyword in text_lower for keyword in chat_keywords):
        return {
            "intent": "chat",
            "conversation_history": conversation_history,
            "pending_question": "",
            "clarification_needed": False,
            "current_phase": "plan",
            "messages": ["[plan] 闲聊问候"],
        }

    # 退出关键词（模糊匹配）
    exit_keywords = ["退出", "exit", "quit", "bye", "再见", "结束", "q"]
    if any(keyword in text_lower for keyword in exit_keywords):
        return {
            "intent": "exit",
            "conversation_history": conversation_history,
            "should_exit": True,
            "current_phase": "done",
            "messages": ["[plan] 用户请求退出"],
        }

    # ========== 规则引擎优先：快速精准匹配单工具请求 ==========
    rule_result = _rule_based_understand(user_input)
    if rule_result and rule_result.get("task_list"):
        target = rule_result["target"]
        task_list = rule_result["task_list"]
        scan_scope = rule_result["scan_scope"]
        target_type = rule_result["target_type"]
        response_to_user = rule_result["response_to_user"]

        # 目标缺失时主动询问（不盲目执行）
        if not target:
            conversation_history.append({
                "role": "agent",
                "content": "我理解您想执行扫描，但没有从输入中提取到有效的目标地址（域名/IP/URL）。请明确指定目标。",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            return {
                "intent": "clarify",
                "conversation_history": conversation_history,
                "pending_question": "请提供明确的扫描目标（域名/IP/URL），例如：扫描 example.com 的端口",
                "clarification_needed": True,
                "current_phase": "plan",
                "messages": ["[plan] 规则引擎匹配到工具但目标缺失，触发澄清"],
            }

        conversation_history.append({
            "role": "agent",
            "content": response_to_user,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

        return {
            "intent": "scan",
            "conversation_history": conversation_history,
            "target": target,
            "target_type": target_type,
            "scan_scope": scan_scope,
            "task_list": task_list,
            "tool_params": {},
            "pending_question": "",
            "clarification_needed": False,
            "current_phase": "plan",
            "skip_cache": state.get("skip_cache", False),
            "messages": [f"[plan] 规则引擎: {rule_result['reasoning']}"],
        }

    # ========== LLM 深度理解：用于规则引擎无法覆盖的复杂场景 ==========
    # 获取 LLM 客户端
    llm = _get_llm_client()

    if llm is None:
        # LLM 不可用且规则引擎也没匹配上，降级到基础模板
        fallback = FALLBACK_TASK_PLAN.copy()
        target = _extract_target_from_input(user_input)
        if target:
            fallback["target"] = target
            fallback["task_list"] = ["whois", "subdomain", "portscan", "report"]

        return {
            "intent": "scan",
            "conversation_history": conversation_history,
            "task_list": fallback["task_list"],
            "target": fallback.get("target", ""),
            "scan_scope": fallback["scan_scope"],
            "pending_question": "",
            "clarification_needed": False,
            "current_phase": "plan",
            "skip_cache": state.get("skip_cache", False),
            "messages": [f"[plan] LLM 不可用，使用基础模板: {fallback['task_list']}"],
        }

    # 构建提示词
    prompt = INTENT_ANALYSIS_PROMPT.format(
        conversation_history=_format_conversation_history(conversation_history),
        user_input=user_input,
        assets=_format_assets(state),
    )

    try:
        # 调用 LLM
        response = llm.invoke(prompt)
        content = response.content if hasattr(response, "content") else str(response)

        # 解析 JSON
        parsed = _parse_llm_response(content)

        intent = parsed.get("intent", "scan")
        clarification_needed = parsed.get("clarification_needed", False)
        pending_question = parsed.get("pending_question", "")
        response_to_user = parsed.get("response_to_user", "")
        target = parsed.get("target", "")
        target_type = parsed.get("target_type", "unknown")
        scan_scope = parsed.get("scan_scope", "full")

        # 构建 Agent 回复加入对话历史
        agent_reply = response_to_user if response_to_user else (
            pending_question if clarification_needed else "好的，开始执行扫描计划..."
        )
        conversation_history.append({
            "role": "agent",
            "content": agent_reply,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

        # 根据意图返回不同更新
        if intent == "exit":
            return {
                "intent": "exit",
                "conversation_history": conversation_history,
                "should_exit": True,
                "current_phase": "done",
                "messages": ["[plan] 用户请求退出"],
            }

        if intent == "chat":
            return {
                "intent": "chat",
                "conversation_history": conversation_history,
                "pending_question": "",
                "clarification_needed": False,
                "current_phase": "plan",
                "messages": [f"[plan] 闲聊: {agent_reply}"],
            }

        if clarification_needed:
            return {
                "intent": "clarify",
                "conversation_history": conversation_history,
                "pending_question": pending_question,
                "clarification_needed": True,
                "current_phase": "plan",
                "messages": [f"[plan] 需要澄清: {pending_question}"],
            }

        # 扫描意图：生成任务列表
        task_list = _build_task_list_from_intent(parsed, state)
        tool_params = parsed.get("tool_params", {})

        # 如果 target 为空但对话历史中有之前的 target，继承
        if not target and state.get("target"):
            target = state.get("target", "")

        return {
            "intent": "scan",
            "conversation_history": conversation_history,
            "target": target,
            "target_type": target_type,
            "scan_scope": scan_scope,
            "task_list": task_list,
            "pending_question": "",
            "clarification_needed": False,
            "current_phase": "plan",
            "skip_cache": state.get("skip_cache", False),
            "messages": [f"[plan] 意图: {intent}, 目标: {target}, 任务: {task_list}"],
        }

    except Exception as e:
        # LLM 调用异常，降级
        target = _extract_target_from_input(user_input)
        fallback_tasks = ["whois", "subdomain", "portscan", "report"] if target else []

        conversation_history.append({
            "role": "agent",
            "content": "遇到一点问题，我先用基础模式帮您扫描...",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

        return {
            "intent": "scan",
            "conversation_history": conversation_history,
            "target": target,
            "task_list": fallback_tasks,
            "pending_question": "",
            "clarification_needed": False,
            "current_phase": "plan",
            "skip_cache": state.get("skip_cache", False),
            "messages": [f"[plan] LLM 异常降级: {e}"],
        }


def _extract_target_from_input(user_input: str) -> str:
    """
    从用户输入中提取可能的扫描目标（启发式）

    优先级：
    1. URL（带协议）> 裸域名 > IP
    2. 复用 dir_scan 的 extract_clean_url 逻辑，确保 URL 提取一致性
    """
    if not user_input:
        return ""

    text = str(user_input).strip()

    # 优先复用 dir_scan 的 URL 自适应提取
    try:
        from tools.active.dir_scan_tool import extract_clean_url
        cleaned = extract_clean_url(text)
        if cleaned:
            return cleaned
    except ImportError:
        pass

    # 降级：自行提取
    import re

    # 匹配 URL（带协议）
    https_match = re.search(r'https?://[^\s\x00-\x1f\x7f`"\'<>\\^|,;]*', text, re.IGNORECASE)
    if https_match:
        candidate = re.sub(r'[`"\'<>\\^|{}\s,;]+$', '', https_match.group(0))
        return candidate

    # 匹配裸域名
    domain_pattern = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    domains = domain_pattern.findall(text)
    for d in domains:
        # 过滤常见误匹配
        if d.lower() not in ("example.com", "test.com", "localhost"):
            return d.lower()

    # 匹配 IP
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = ip_pattern.findall(text)
    for ip in ips:
        return ip

    return ""