# 工具基类模块
# 统一封装缓存、超时、重试逻辑，所有具体工具需继承此类并实现 execute 方法

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from tools.result_model import ToolResult
from utils.cache_helper import get_cache, set_cache


class BaseTool(ABC):
    """
    工具抽象基类，所有具体工具必须继承此类并实现 execute 方法

    统一提供：
    - 缓存：优先读取 TTL 缓存，命中直接返回
    - 超时：单工具独立超时隔离
    - 重试：指数退避重试机制
    - 统一返回：所有工具返回 ToolResult 格式
    """

    # 子类需覆盖的属性
    tool_name: str = "base_tool"
    description: str = ""
    timeout: int = 10          # 单工具超时（秒）
    max_retries: int = 2       # 最大重试次数
    cache_ttl: int = 3600      # 缓存 TTL（秒）
    is_passive: bool = True    # 是否为被动工具（无发包）

    @abstractmethod
    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> Any:
        """
        子类实现的具体执行逻辑

        Args:
            target: 扫描目标（域名/IP/URL）
            params: 工具额外参数

        Returns:
            工具执行的原始结果数据
        """
        ...

    async def execute(self, target: str, params: dict[str, Any] | None = None) -> ToolResult:
        """
        统一执行入口，封装缓存、重试、超时、计时逻辑

        Args:
            target: 扫描目标
            params: 工具额外参数（支持 skip_cache=True 跳过缓存）

        Returns:
            ToolResult: 统一格式的执行结果
        """
        start_time = time.time()
        params = params or {}
        skip_cache = params.get("skip_cache", False)

        # 1. 优先读取缓存（支持跳过缓存）
        cache_key = f"{self.tool_name}:{target}"
        if not skip_cache:
            cached = get_cache(cache_key)
            if cached is not None:
                return ToolResult(
                    success=True,
                    data=cached,
                    error=None,
                    elapsed=0.0,
                    target=target,
                    tool_name=self.tool_name,
                    from_cache=True,
                )
        else:
            # 强制跳过缓存：清理该 key 防止后续读取
            from utils.cache_helper import clear_cache
            clear_cache(cache_key)

        # 2. 循环重试（指数退避）
        last_error = None
        # max_retries=0 表示不重试，但至少执行 1 次
        max_attempts = max(self.max_retries, 1)
        for attempt in range(1, max_attempts + 1):
            try:
                # 带超时执行
                result_data = await asyncio.wait_for(
                    self._execute(target, params),
                    timeout=self.timeout,
                )

                # 执行成功，写入缓存
                elapsed = time.time() - start_time
                set_cache(cache_key, result_data, ttl=self.cache_ttl)

                return ToolResult(
                    success=True,
                    data=result_data,
                    error=None,
                    elapsed=elapsed,
                    target=target,
                    tool_name=self.tool_name,
                    from_cache=False,
                )

            except asyncio.TimeoutError:
                last_error = f"工具 {self.tool_name} 执行超时（{self.timeout}s），第 {attempt} 次重试"
            except Exception as e:
                last_error = f"工具 {self.tool_name} 执行异常: {str(e)}，第 {attempt} 次重试"

            # 指数退避等待（最后一次不等待）
            if attempt < max_attempts:
                wait_time = 2 ** attempt
                await asyncio.sleep(wait_time)

        # 3. 全部重试失败
        elapsed = time.time() - start_time
        return ToolResult(
            success=False,
            data=None,
            error=last_error,
            elapsed=elapsed,
            target=target,
            tool_name=self.tool_name,
            from_cache=False,
        )