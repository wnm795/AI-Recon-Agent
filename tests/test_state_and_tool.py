# 单元测试：ReconState 与 ToolResult 实例化验证

import sys
from pathlib import Path

# 确保项目根目录在 Python 路径中
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import pytest
from typing import Annotated, get_origin, get_args
from workflow.state import ReconState
from tools.result_model import ToolResult
from tools.base import BaseTool


# ==================== ReconState 测试 ====================

class TestReconState:
    """ReconState 状态模型测试（TypedDict）"""

    def test_create_state_with_target(self):
        """测试带目标初始化"""
        state: ReconState = {"target": "example.com", "target_type": "domain"}
        assert state["target"] == "example.com"
        assert state["target_type"] == "domain"

    def test_create_state_with_assets(self):
        """测试资产字段初始化"""
        state: ReconState = {
            "subdomains": ["sub1.example.com", "sub2.example.com"],
            "ips": ["1.2.3.4"],
            "open_ports": [{"ip": "1.2.3.4", "port": 80, "service": "http"}],
        }
        assert len(state["subdomains"]) == 2
        assert state["ips"][0] == "1.2.3.4"
        assert state["open_ports"][0]["port"] == 80

    def test_state_cdn_fields(self):
        """测试 CDN 相关字段"""
        state: ReconState = {"has_cdn": True, "real_ip": "5.6.7.8"}
        assert state["has_cdn"] is True
        assert state["real_ip"] == "5.6.7.8"

    def test_state_has_reducer_annotations(self):
        """测试 reducer 字段带有 Annotated 注解"""
        # 获取 ReconState 的类型注解
        annotations = ReconState.__annotations__
        assert "target" in annotations
        assert "subdomains" in annotations
        assert "messages" in annotations

        # 验证 messages 字段有 reducer（Annotated）
        messages_type = annotations["messages"]
        assert get_origin(messages_type) is Annotated

        # 验证 target 字段无 reducer（普通 str）
        target_type = annotations["target"]
        assert target_type is str


# ==================== ToolResult 测试 ====================

class TestToolResult:
    """ToolResult 数据模型测试"""

    def test_success_result(self):
        """测试成功结果"""
        result = ToolResult(
            success=True,
            data={"registrar": "Example Corp"},
            elapsed=1.23,
            target="example.com",
            tool_name="whois_query",
        )
        assert result.success is True
        assert result.data["registrar"] == "Example Corp"
        assert result.error is None
        assert result.elapsed == 1.23
        assert result.target == "example.com"
        assert result.tool_name == "whois_query"
        assert result.from_cache is False

    def test_failure_result(self):
        """测试失败结果"""
        result = ToolResult(
            success=False,
            error="连接超时",
            elapsed=10.5,
            target="example.com",
            tool_name="port_scan",
        )
        assert result.success is False
        assert result.data is None
        assert result.error == "连接超时"

    def test_cache_result(self):
        """测试缓存命中结果"""
        result = ToolResult(
            success=True,
            data={"cached": True},
            elapsed=0.0,
            target="example.com",
            tool_name="dns_enum",
            from_cache=True,
        )
        assert result.from_cache is True
        assert result.elapsed == 0.0

    def test_default_values(self):
        """测试默认值"""
        result = ToolResult(success=True)
        assert result.data is None
        assert result.error is None
        assert result.elapsed == 0.0
        assert result.target == ""
        assert result.tool_name == ""
        assert result.from_cache is False


# ==================== BaseTool 测试 ====================

class TestBaseTool:
    """BaseTool 抽象类测试"""

    def test_cannot_instantiate_directly(self):
        """测试不能直接实例化抽象类"""
        with pytest.raises(TypeError):
            BaseTool()

    def test_subclass_implementation(self):
        """测试子类实现"""
        class MockTool(BaseTool):
            tool_name = "mock_tool"
            description = "测试工具"
            timeout = 5
            max_retries = 1

            async def _execute(self, target, params=None):
                return {"mock": True, "target": target}

        tool = MockTool()
        assert tool.tool_name == "mock_tool"
        assert tool.timeout == 5
        assert tool.max_retries == 1
        assert tool.is_passive is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])