# 全局状态定义模块
# 定义 ReconState 全局状态结构，明确 reducer 追加字段与直接覆盖字段的更新规约

from typing import Annotated, Any, TypedDict
from operator import add


# ==================== LangGraph 状态定义（TypedDict + Annotated） ====================

class ReconState(TypedDict, total=False):
    """
    LangGraph 全局唯一状态载体（含对话交互字段）

    更新规约：
    - Annotated[type, add]：增量追加（新数据合并到已有数据，不覆盖）
    - 无 Annotated：直接覆盖（新值替换旧值）
    """

    # -------- 对话交互字段（直接覆盖） --------
    user_input: str                           # 当前用户输入
    conversation_history: list[dict]          # 对话历史 [{role, content, timestamp}]
    pending_question: str | None              # Agent 待澄清的问题
    clarification_needed: bool                # 是否需要用户澄清
    scan_scope: str                           # 扫描范围：full / passive / active
    should_exit: bool                         # 是否退出对话
    intent: str                               # 用户意图：scan / chat / exit

    # -------- 扫描目标字段（直接覆盖） --------
    target: str
    target_type: str                          # domain / ip / url
    current_phase: str                        # init / plan / passive / active / analyze / report / done
    has_cdn: bool
    has_waf: bool
    real_ip: str
    iteration: int
    max_iterations: int
    new_asset_found: bool
    skip_cache: bool                          # 是否跳过缓存（由 /fresh 命令控制）

    # -------- 信息收集结果字段（直接覆盖） --------
    whois_info: dict[str, Any]
    dns_records: list[dict]
    icp_info: dict[str, Any]

    # -------- reducer 追加字段 --------
    messages: Annotated[list[str], add]       # 流程消息日志
    completed_tasks: Annotated[list[str], add]  # 已完成任务列表
    errors: Annotated[list[str], add]         # 错误信息列表

    # -------- 直接覆盖字段 --------
    task_list: list[str]                      # 当前待执行任务列表（每次覆盖）

    # -------- 资产发现字段（reducer 追加） --------
    subdomains: Annotated[list[str], add]
    ips: Annotated[list[str], add]
    open_ports: Annotated[list[dict], add]
    fingerprints: Annotated[list[dict], add]
    sensitive_paths: Annotated[list[dict], add]
    apis: Annotated[list[dict], add]
    screenshots: Annotated[list[dict], add]
    vuln_hints: Annotated[list[dict], add]
    leak_info: Annotated[list[dict], add]
    discovered_assets: Annotated[list[str], add]