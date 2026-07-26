# 文件缓存辅助模块
# 提供缓存文件读写、TTL 过期检测与自动清理功能

import json
import time
from pathlib import Path
from typing import Any, Optional

from config.settings import CACHE_DIR


# 内存缓存字典，作为默认实现（后续可替换为文件缓存）
_cache_store: dict[str, dict] = {}


def get_cache(key: str) -> Any | None:
    """
    读取缓存

    Args:
        key: 缓存键名

    Returns:
        缓存数据，过期或不存在时返回 None
    """
    entry = _cache_store.get(key)
    if entry is None:
        return None

    # 检查 TTL 过期
    if entry["expires_at"] < time.time():
        del _cache_store[key]
        return None

    return entry["data"]


def set_cache(key: str, data: Any, ttl: int = 3600) -> None:
    """
    写入缓存

    Args:
        key: 缓存键名
        data: 缓存数据
        ttl: 缓存存活时间（秒）。ttl<=0 表示不缓存（写入空操作）

    注意：
        Windows 平台下 time.time() 精度约 15ms，ttl=1 在毫秒级调用间隔下
        也会命中缓存（expires_at ≈ time.time()），因此 ttl<=0 视为"不缓存"
    """
    if ttl <= 0:
        return  # 不缓存（避免 Windows time.time() 精度问题导致 ttl=0 仍命中）
    _cache_store[key] = {
        "data": data,
        "expires_at": time.time() + ttl,
    }


def clear_cache(key: str | None = None) -> None:
    """
    清理缓存

    Args:
        key: 指定清理的缓存键，为 None 时清理全部过期缓存
    """
    if key:
        _cache_store.pop(key, None)
    else:
        # 清理所有过期缓存
        now = time.time()
        expired_keys = [k for k, v in _cache_store.items() if v["expires_at"] < now]
        for k in expired_keys:
            del _cache_store[k]


def clear_all_cache() -> None:
    """清理全部缓存（包括未过期的）"""
    _cache_store.clear()