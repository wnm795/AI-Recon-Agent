# WHOIS 工具单元测试
# 验证注册表查询、工具实例化、WHOIS 查询执行与 ToolResult 返回

import asyncio
import sys
from pathlib import Path

# 确保项目根目录在 Python 路径中
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import pytest
from tools.registry import TOOL_REGISTRY, get_tool, list_tools
from tools.passive.whois_tool import WhoisTool
from tools.result_model import ToolResult
from utils.cache_helper import clear_all_cache


class TestToolRegistry:
    """工具注册表测试"""

    def test_whois_registered(self):
        """测试 whois 工具已注册到注册表"""
        assert "whois" in TOOL_REGISTRY
        tool = TOOL_REGISTRY["whois"]
        assert isinstance(tool, WhoisTool)

    def test_get_tool_exists(self):
        """测试 get_tool 能获取已注册工具"""
        tool = get_tool("whois")
        assert tool is not None
        assert isinstance(tool, WhoisTool)
        assert tool.tool_name == "whois"

    def test_get_tool_not_exists(self):
        """测试获取不存在的工具返回 None"""
        assert get_tool("not_exist_tool") is None

    def test_list_tools(self):
        """测试列出所有工具"""
        tools = list_tools()
        assert "whois" in tools


class TestWhoisToolExecute:
    """WhoisTool 执行测试"""

    @pytest.fixture(autouse=True)
    def clear_cache_before(self):
        """每个测试前清理缓存，避免缓存干扰"""
        clear_all_cache()

    def test_execute_example_com(self):
        """
        验证：调用 get_tool("whois").execute("example.com") 返回 ToolResult
        由于 example.com 是 IANA 保留域名，whois 查询可能返回空或特定结果，
        此处主要验证返回格式正确。
        """
        tool = get_tool("whois")
        assert tool is not None

        result = asyncio.run(tool.execute("example.com"))

        # 验证返回类型
        assert isinstance(result, ToolResult)

        # 验证基本字段
        assert result.target == "example.com"
        assert result.tool_name == "whois"
        assert result.elapsed >= 0.0

        # 由于 example.com 是保留域名，可能 success=False，也可能返回空数据
        # 我们主要验证格式正确，不强制要求 success=True
        if result.success:
            assert isinstance(result.data, dict)
            assert "domain" in result.data
            assert result.error is None
        else:
            assert result.error is not None

    def test_whois_tool_attributes(self):
        """测试 whois 工具属性配置正确"""
        tool = get_tool("whois")
        assert tool.tool_name == "whois"
        assert tool.timeout == 10
        assert tool.max_retries == 2
        assert tool.cache_ttl == 3600
        assert tool.is_passive is True

    def test_execute_with_cache(self):
        """测试缓存命中机制：第二次调用应从缓存返回"""
        tool = get_tool("whois")

        # 第一次执行
        result1 = asyncio.run(tool.execute("example.com"))
        assert result1.from_cache is False

        # 第二次执行（应从缓存命中）
        result2 = asyncio.run(tool.execute("example.com"))
        assert result2.from_cache is True
        assert result2.elapsed == 0.0
        assert result2.data == result1.data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])