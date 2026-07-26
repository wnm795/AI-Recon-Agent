# 漏洞匹配分析节点
# 调用知识库 match_vuln 方法，根据中间件版本检索 CVE，存入 vuln_hints

from typing import Any


def analyze_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    分析节点：基于发现的指纹和端口信息进行漏洞匹配

    当前为简化实现：
    - 根据已识别指纹中的组件和版本，匹配常见 CVE
    - 根据开放端口识别潜在风险服务
    """
    fingerprints = state.get("fingerprints", [])
    open_ports = state.get("open_ports", [])

    vuln_hints = []

    # 基于指纹的漏洞匹配（简化版，后续可接入向量知识库）
    for fp in fingerprints:
        name = fp.get("name", "").lower()
        version = fp.get("version", "")

        # 常见组件的已知漏洞（示例规则）
        if "nginx" in name and version:
            try:
                v_parts = version.split(".")
                major = int(v_parts[0]) if v_parts else 0
                minor = int(v_parts[1]) if len(v_parts) > 1 else 0
                if major < 1 or (major == 1 and minor < 18):
                    vuln_hints.append({
                        "component": "nginx",
                        "version": version,
                        "cve": "CVE-2019-9511",
                        "severity": "high",
                        "description": "HTTP/2 拒绝服务漏洞",
                    })
            except (ValueError, IndexError):
                pass

        if "apache" in name and version:
            try:
                v_parts = version.split(".")
                major = int(v_parts[0]) if v_parts else 0
                if major < 2:
                    vuln_hints.append({
                        "component": "Apache HTTP Server",
                        "version": version,
                        "cve": "CVE-2021-44790",
                        "severity": "critical",
                        "description": "路径遍历/代码执行漏洞",
                    })
            except (ValueError, IndexError):
                pass

    # 基于端口的风险提示
    high_risk_ports = {21: "FTP", 23: "Telnet", 3389: "RDP", 445: "SMB", 135: "RPC"}
    for port_info in open_ports:
        port_num = port_info.get("port", 0)
        if port_num in high_risk_ports:
            vuln_hints.append({
                "component": high_risk_ports[port_num],
                "version": "",
                "cve": "",
                "severity": "medium",
                "description": f"高风险服务 {high_risk_ports[port_num]} 暴露在端口 {port_num}",
            })

    messages = [f"[analyze] 漏洞分析完成，发现 {len(vuln_hints)} 个风险提示"]

    return {
        "current_phase": "analyze",
        "vuln_hints": vuln_hints,
        "messages": messages,
    }
