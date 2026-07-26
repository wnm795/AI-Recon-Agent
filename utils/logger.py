# 结构化日志工具模块
# 提供 JSON 格式结构化日志输出，支持按目标、工具、阶段分目录存储

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from config.settings import LOGS_DIR, LOG_LEVEL


# 日志级别映射
LEVEL_MAP = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
CURRENT_LEVEL = LEVEL_MAP.get(LOG_LEVEL.upper(), 20)


def _log(level: str, message: str, **extra) -> None:
    """内部日志输出函数"""
    level_num = LEVEL_MAP.get(level, 20)
    if level_num < CURRENT_LEVEL:
        return

    entry = {
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "message": message,
    }
    entry.update(extra)

    # 输出到 stderr
    print(json.dumps(entry, ensure_ascii=False), file=sys.stderr)


def log_debug(message: str, **extra) -> None:
    """调试日志"""
    _log("DEBUG", message, **extra)


def log_info(message: str, **extra) -> None:
    """信息日志"""
    _log("INFO", message, **extra)


def log_warning(message: str, **extra) -> None:
    """警告日志"""
    _log("WARNING", message, **extra)


def log_error(message: str, **extra) -> None:
    """错误日志"""
    _log("ERROR", message, **extra)


def save_structured_log(
    target: str,
    phase: str,
    data: dict[str, Any],
    log_type: str = "info",
) -> Path:
    """
    保存结构化日志到文件

    Args:
        target: 扫描目标
        phase: 阶段名称
        data: 日志数据
        log_type: 日志类型（passive/active/error）

    Returns:
        日志文件路径
    """
    log_dir = LOGS_DIR / log_type
    log_dir.mkdir(parents=True, exist_ok=True)

    safe_target = target.replace(".", "_").replace(":", "_") if target else "unknown"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"{safe_target}_{phase}_{timestamp}.json"

    entry = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "phase": phase,
        "data": data,
    }

    log_file.write_text(json.dumps(entry, ensure_ascii=False, indent=2), encoding="utf-8")
    return log_file
