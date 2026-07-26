# 错误容灾处理节点
# 区分网络超时类可重试错误、致命错误、普通异常
# 可重试任务放回任务队列，其余直接跳过

from typing import Any


def error_handler_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    错误处理节点：读取状态中的 errors，进行容错决策

    可重试错误（超时、连接失败）：放回 task_list
    致命错误（工具不存在、权限不足）：记录并跳过
    """
    errors = state.get("errors", [])
    task_list = state.get("task_list", [])

    if not errors:
        return {
            "messages": ["[error_handler] 无错误需要处理"],
        }

    retryable_keywords = ["超时", "timeout", "连接", "connection", "retry", "暂时"]
    retry_tasks = []
    fatal_errors = []
    skipped = []

    for err in errors:
        err_lower = err.lower()
        is_retryable = any(kw in err_lower for kw in retryable_keywords)

        # 尝试提取工具名
        tool_name = ""
        if ":" in err:
            tool_name = err.split(":")[0].strip()

        if is_retryable and tool_name:
            retry_tasks.append(tool_name)
        elif "未注册" in err or "未安装" in err or "not found" in err_lower:
            skipped.append(err)
        else:
            fatal_errors.append(err)

    updates: dict[str, Any] = {
        "messages": [f"[error_handler] 处理 {len(errors)} 个错误"],
    }

    if retry_tasks:
        updates["task_list"] = retry_tasks
        updates["messages"].append(f"[error_handler] 可重试任务放回队列: {retry_tasks}")

    if fatal_errors:
        updates["messages"].append(f"[error_handler] 致命错误: {fatal_errors}")

    if skipped:
        updates["messages"].append(f"[error_handler] 已跳过: {skipped}")

    # 清空已处理的错误（保留致命错误用于报告）
    updates["errors"] = fatal_errors

    return updates
