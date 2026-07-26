# 漏洞匹配分析工具
# 基于 Chroma 向量库存储的 NVD CVE 数据，进行组件版本漏洞匹配

from typing import Any

from knowledge.loaders.cve_loader import get_cve_count, search_cves
from tools.base import BaseTool


class VulnMatchTool(BaseTool):
    """
    漏洞匹配分析工具

    基于本地 Chroma 向量库中的 NVD CVE 数据，结合指纹和端口信息进行漏洞匹配。
    通过 RAG 语义检索召回相关 CVE，再用 CPE 版本范围做精确过滤。
    """

    tool_name = "vuln_match"
    description = "组件版本 CVE 漏洞匹配"
    timeout = 30
    max_retries = 1
    cache_ttl = 3600
    is_passive = True

    # 保留端口风险规则（非 CVE，纯暴露风险提示）
    HIGH_RISK_PORTS = {
        21: "FTP",
        23: "Telnet",
        3389: "RDP",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
    }

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        执行漏洞匹配

        Args:
            target: 扫描目标
            params:
                - fingerprints: Web 指纹列表，如 [{"name": "nginx", "version": "1.18.0"}]
                - open_ports: 开放端口列表，如 [{"port": 80, "service": "http"}]
                - top_k: RAG 检索条数（默认 15）

        Returns:
            {"target": target, "vuln_hints": [...], "count": int}
        """
        fingerprints = (params or {}).get("fingerprints", [])
        open_ports = (params or {}).get("open_ports", [])
        top_k = (params or {}).get("top_k", 15)

        vuln_hints = []

        # 检查本地 CVE 知识库是否可用
        cve_count = get_cve_count()
        if cve_count == 0:
            print("[vuln_match] 本地 CVE 知识库为空，请先运行: python scripts/sync_cve_task.py")

        # 基于指纹做 RAG 漏洞匹配
        for fp in fingerprints:
            name = fp.get("name", "").strip()
            version = fp.get("version", "").strip()
            if not name:
                continue

            matched = self._match_fingerprint(name, version, top_k)
            for cve in matched:
                vuln_hints.append({
                    "component": name,
                    "version": version,
                    "cve": cve["cve_id"],
                    "severity": cve["severity"],
                    "cvss_score": cve["cvss_score"],
                    "description": cve["description"][:300],
                    "source": "rag_cve",
                })

        # 端口风险（保留原有逻辑）
        for p in open_ports:
            port = p.get("port", 0)
            if port in self.HIGH_RISK_PORTS:
                vuln_hints.append({
                    "component": self.HIGH_RISK_PORTS[port],
                    "version": "",
                    "cve": "",
                    "severity": "medium",
                    "description": f"{self.HIGH_RISK_PORTS[port]} 服务暴露在公网端口 {port}",
                    "source": "port_risk",
                })

        # 去重：相同 (component, version, cve) 只保留一条
        seen = set()
        unique_hints = []
        for hint in vuln_hints:
            key = (hint.get("component", ""), hint.get("version", ""), hint.get("cve", ""))
            if key in seen:
                continue
            seen.add(key)
            unique_hints.append(hint)

        return {
            "target": target,
            "vuln_hints": unique_hints,
            "count": len(unique_hints),
        }

    def _match_fingerprint(self, name: str, version: str, top_k: int) -> list[dict[str, Any]]:
        """
        对单个指纹进行 RAG 检索 + 版本过滤

        Args:
            name: 组件名称，如 "nginx"
            version: 组件版本，如 "1.18.0"
            top_k: 检索条数

        Returns:
            匹配到的 CVE 列表
        """
        query = f"{name} {version} vulnerability CVE".strip()
        candidates = search_cves(query, top_k=top_k)

        matched = []
        for cve in candidates:
            if self._is_fingerprint_affected(name, version, cve):
                matched.append(cve)

        return matched

    def _is_fingerprint_affected(self, name: str, version: str, cve: dict[str, Any]) -> bool:
        """
        判断指纹是否受 CVE 影响

        规则：
        1. 指纹名称必须匹配 CVE 的某个 CPE 配置（vendor 或 product）
        2. 若提供了版本号，版本必须在 CPE 版本范围内
        """
        name_lower = name.lower()
        name_tokens = [t for t in name_lower.replace("-", " ").replace("_", " ").split() if t]

        for config in cve.get("cpe_configs", []):
            vendor = config.get("vendor", "")
            product = config.get("product", "")
            target_str = f"{vendor} {product}"

            # 名称匹配：指纹所有 token 都出现在 vendor+product 中
            if not all(token in target_str for token in name_tokens):
                continue

            # 未提供版本号时，保守认为可能受影响（但这里返回 True 会召回过多）
            # 实际场景中建议要求提供版本号，这里做精确匹配：无版本不匹配
            if not version:
                return False

            if self._version_in_range(
                version,
                config.get("version_start", ""),
                config.get("version_start_including", False),
                config.get("version_end", ""),
                config.get("version_end_including", False),
            ):
                return True

        return False

    @staticmethod
    def _version_to_tuple(version: str) -> tuple[int, ...]:
        """把版本字符串转为整数元组，便于比较"""
        parts = []
        for part in version.split("."):
            # 提取前导数字
            num_str = ""
            for ch in part:
                if ch.isdigit():
                    num_str += ch
                else:
                    break
            parts.append(int(num_str) if num_str else 0)
        return tuple(parts)

    def _version_in_range(
        self,
        version: str,
        start: str,
        start_including: bool,
        end: str,
        end_including: bool,
    ) -> bool:
        """
        判断版本是否在 [start, end] 范围内

        start_including / end_including 控制边界是否包含
        """
        try:
            v_tuple = self._version_to_tuple(version)
            s_tuple = self._version_to_tuple(start) if start else None
            e_tuple = self._version_to_tuple(end) if end else None
        except Exception:
            return False

        if s_tuple is not None:
            if start_including:
                if v_tuple < s_tuple:
                    return False
            else:
                if v_tuple <= s_tuple:
                    return False

        if e_tuple is not None:
            if end_including:
                if v_tuple > e_tuple:
                    return False
            else:
                if v_tuple >= e_tuple:
                    return False

        return True
