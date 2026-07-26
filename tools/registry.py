# 工具注册表 / 工厂模块
# 维护全局 TOOL_REGISTRY 映射：任务名 -> 工具实例，实现任务与工具解耦

from typing import Optional

from tools.base import BaseTool

# 导入所有具体工具
from tools.passive.whois_tool import WhoisTool
from tools.passive.dns_enum_tool import DnsEnumTool
from tools.passive.subdomain_tool import SubdomainTool
from tools.passive.icp_tool import IcpTool
from tools.passive.github_leak_tool import GithubLeakTool
from tools.passive.wayback_tool import WaybackTool
from tools.passive.cert_log_tool import CertLogTool

from tools.active.cdn_detect_tool import CdnDetectTool
from tools.active.cdn_bypass_tool import CdnBypassTool
from tools.active.port_scan_tool import PortScanTool
from tools.active.http_fingerprint import HttpFingerprintTool
from tools.active.dir_scan_tool import DirScanTool
from tools.active.api_discover import ApiDiscoverTool
from tools.active.screenshot_tool import ScreenshotTool

from tools.analysis.vuln_match_tool import VulnMatchTool
from tools.analysis.report_tool import ReportTool


# 全局工具注册表：任务名 -> 工具实例映射
TOOL_REGISTRY: dict[str, BaseTool] = {
    # 被动信息收集工具
    "whois": WhoisTool(),
    "dns_enum": DnsEnumTool(),
    "subdomain": SubdomainTool(),
    "icp": IcpTool(),
    "github_leak": GithubLeakTool(),
    "wayback": WaybackTool(),
    "cert_log": CertLogTool(),
    # 主动扫描工具
    "cdn_detect": CdnDetectTool(),
    "cdn_bypass": CdnBypassTool(),
    "portscan": PortScanTool(),
    "http_fingerprint": HttpFingerprintTool(),
    "dir_scan": DirScanTool(),
    "api_discover": ApiDiscoverTool(),
    "screenshot": ScreenshotTool(),
    # 分析工具
    "vuln_match": VulnMatchTool(),
    "report": ReportTool(),
}


def get_tool(tool_name: str) -> Optional[BaseTool]:
    """
    根据任务名获取对应工具实例

    Args:
        tool_name: 注册表中的工具名称

    Returns:
        BaseTool 实例，未找到时返回 None
    """
    return TOOL_REGISTRY.get(tool_name)


def register_tool(tool_name: str, tool_instance: BaseTool) -> None:
    """
    动态注册工具到注册表

    Args:
        tool_name: 工具名称
        tool_instance: 工具实例
    """
    TOOL_REGISTRY[tool_name] = tool_instance


def list_tools() -> list[str]:
    """
    列出所有已注册的工具名称

    Returns:
        工具名称列表
    """
    return list(TOOL_REGISTRY.keys())


def get_passive_tools() -> list[str]:
    """获取所有被动工具名称"""
    return [name for name, tool in TOOL_REGISTRY.items() if tool.is_passive]


def get_active_tools() -> list[str]:
    """获取所有主动工具名称"""
    return [name for name, tool in TOOL_REGISTRY.items() if not tool.is_passive]
