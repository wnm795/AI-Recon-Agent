# 请求限流工具模块
# 控制单目标每秒请求频率，防止触发封禁策略

import asyncio
import time
from collections import defaultdict
from typing import Optional

from config.settings import RATE_LIMIT_PER_SECOND


class RateLimiter:
    """
    基于令牌桶算法的请求限流器

    按目标域名/IP 分别限流，防止触发对方的封禁策略
    """

    def __init__(self, rate: int = RATE_LIMIT_PER_SECOND):
        """
        Args:
            rate: 每秒最大请求数
        """
        self.rate = rate
        self.tokens: dict[str, float] = defaultdict(lambda: float(rate))
        self.last_update: dict[str, float] = defaultdict(time.time)
        self._lock = asyncio.Lock()

    async def acquire(self, target: str) -> None:
        """
        获取一个请求令牌，如果没有可用令牌则等待

        Args:
            target: 目标标识（域名/IP），按目标分别限流
        """
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_update[target]

            # 补充令牌
            self.tokens[target] = min(
                self.rate,
                self.tokens[target] + elapsed * self.rate,
            )
            self.last_update[target] = now

            if self.tokens[target] < 1:
                # 需要等待
                wait_time = (1 - self.tokens[target]) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens[target] = 0
            else:
                self.tokens[target] -= 1

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


# 全局限流器实例
_global_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """获取全局限流器实例"""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter()
    return _global_limiter
