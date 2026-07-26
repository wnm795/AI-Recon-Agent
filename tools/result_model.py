# 工具统一返回数据模型
# 定义 ToolResult 结构：执行状态、返回数据、错误信息、耗时、目标、工具名

from typing import Any, Optional
from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    """
    所有工具的统一返回数据模型

    无论工具执行成功或失败，均返回此格式，
    便于上层节点统一处理、收集与日志记录。
    """

    success: bool = Field(description="执行是否成功")
    data: Any = Field(default=None, description="工具返回的原始数据")
    error: Optional[str] = Field(default=None, description="错误信息，成功时为 None")
    elapsed: float = Field(default=0.0, description="执行耗时（秒）")
    target: str = Field(default="", description="扫描目标")
    tool_name: str = Field(default="", description="工具名称")
    from_cache: bool = Field(default=False, description="结果是否来自缓存")

    model_config = {"arbitrary_types_allowed": True}