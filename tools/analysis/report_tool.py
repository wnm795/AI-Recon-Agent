# 多格式报告生成工具
# 整合全量扫描数据，基于 Jinja2 模板渲染输出 md/json/csv 报告

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template

from tools.base import BaseTool
from config.settings import REPORTS_DIR


# Markdown 报告模板
MARKDOWN_TEMPLATE = """\
# AI 渗透测试信息收集报告

**目标**: {{ target }}
**生成时间**: {{ generated_at }}
**迭代轮次**: {{ iteration }}

---

## 1. WHOIS 注册信息

{% if whois_info %}
| 字段 | 值 |
|------|------|
{% for key, value in whois_info.items() %}
| {{ key }} | {{ value }} |
{% endfor %}
{% else %}
> 未获取到 WHOIS 信息
{% endif %}

---

## 2. 子域名发现

{% if subdomains %}
**共发现 {{ subdomains | length }} 个子域名**

| 序号 | 子域名 |
|------|--------|
{% for sub in subdomains %}
| {{ loop.index }} | {{ sub }} |
{% endfor %}
{% else %}
> 未发现子域名
{% endif %}

---

## 3. 开放端口

{% if open_ports %}
**共发现 {{ open_ports | length }} 个开放端口**

| IP | 端口 | 协议 | 服务 |
|----|------|------|------|
{% for port in open_ports %}
| {{ port.ip }} | {{ port.port }} | {{ port.protocol }} | {{ port.service }} |
{% endfor %}
{% else %}
> 未发现开放端口
{% endif %}

---

## 4. IP 地址

{% if ip_domain_map %}
**共发现 {{ ip_domain_map | length }} 个唯一 IP 地址**

| IP 地址 | 关联域名 |
|---------|----------|
{% for ip, domains in ip_domain_map.items() %}
| {{ ip }} | {{ ", ".join(domains) }} |
{% endfor %}
{% else %}
> 未发现 IP 地址
{% endif %}

---

## 5. CDN/WAF 识别

{% if has_cdn or has_waf %}
| 类型 | 状态 |
|------|------|
| CDN | {{ "已识别" if has_cdn else "未识别" }} |
| WAF | {{ "已识别" if has_waf else "未识别" }} |
{% if real_ip %}
| 真实 IP | {{ real_ip }} |
{% endif %}
{% else %}
> 未检测到 CDN/WAF
{% endif %}

---

## 6. Web 指纹识别

{% if fingerprints %}
**共发现 {{ fingerprints | length }} 个指纹信息**

| 目标 | 技术栈 | 版本 | 详情 |
|------|--------|------|------|
{% for fp in fingerprints %}
| {{ fp.url | default(fp.target | default("未知")) }} | {{ fp.name | default("未知") }} | {{ fp.version | default("未知") }} | {{ fp.detail | default("") }} |
{% endfor %}
{% else %}
> 未获取到 Web 指纹信息
{% endif %}

---

## 7. 敏感目录爆破

{% if sensitive_paths %}
**共发现 {{ sensitive_paths | length }} 个敏感路径**

| 路径 | 状态码 | 大小 | 目标 |
|------|--------|------|------|
{% for path in sensitive_paths %}
| {{ path.path | default(path.url | default("未知")) }} | {{ path.status | default(path.status_code | default("未知")) }} | {{ path.length | default(path.size | default("未知")) }} | {{ path.target | default(path.url | default("未知")) }} |
{% endfor %}
{% else %}
> 未发现敏感目录
{% endif %}

---

## 8. API 接口发现

{% if apis %}
**共发现 {{ apis | length }} 个潜在 API 端点**

| 端点 | 方法 | 来源 |
|------|------|------|
{% for api in apis %}
| {{ api.endpoint | default("未知") }} | {{ api.method | default("GET") }} | {{ api.source | default("未知") }} |
{% endfor %}
{% else %}
> 未发现 API 接口
{% endif %}

---

## 9. 页面截图

{% if screenshots %}
**共生成 {{ screenshots | length }} 张页面截图**

| 目标 | 截图路径 |
|------|----------|
{% for screenshot in screenshots %}
| {{ screenshot.target | default("未知") }} | {{ screenshot.path | default("未知") }} |
{% endfor %}
{% else %}
> 未生成页面截图（可能未安装 Playwright）
{% endif %}

---

## 10. CVE 漏洞匹配

{% if vuln_hints %}
**共发现 {{ vuln_hints | length }} 个潜在漏洞风险**

| 组件 | 版本 | 漏洞编号 | 风险等级 | 描述 |
|------|------|----------|----------|------|
{% for vuln in vuln_hints %}
| {{ vuln.component | default("未知") }} | {{ vuln.version | default("未知") }} | {{ vuln.cve | default("未知") }} | {{ vuln.severity | default("未知") }} | {{ vuln.description | default("") }} |
{% endfor %}
{% else %}
> 未发现匹配的 CVE 漏洞
{% endif %}

---

## 11. 企业备案信息

{% if icp_info %}
| 字段 | 值 |
|------|------|
{% for key, value in icp_info.items() %}
| {{ key }} | {{ value }} |
{% endfor %}
{% else %}
> 未获取到企业备案信息
{% endif %}

---

## 12. 代码仓库配置泄露

{% if leak_info %}
**共发现 {{ leak_info | length }} 个潜在泄露信息**

| 类型 | 来源 | 详情 |
|------|------|------|
{% for leak in leak_info %}
| {{ leak.type | default("未知") }} | {{ leak.source | default("未知") }} | {{ leak.details | default("") }} |
{% endfor %}
{% else %}
> 未发现代码仓库配置泄露
{% endif %}

---

## 13. 错误日志

{% if errors %}
{% for error in errors %}
- {{ error }}
{% endfor %}
{% else %}
> 无错误
{% endif %}

---

## 14. 流程消息

{% for msg in messages %}
- {{ msg }}
{% endfor %}

---

*报告由 AI Recon Agent 自动生成*
"""


class ReportTool(BaseTool):
    """
    多格式报告生成工具

    从 State 提取数据，使用 Jinja2 模板渲染生成 Markdown 报告
    支持 md/json/csv 格式导出
    """

    tool_name = "report"
    description = "整合全量扫描数据，生成多格式风险报告"
    timeout = 30
    max_retries = 1
    cache_ttl = 0          # 报告不缓存
    is_passive = True

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        生成扫描报告

        Args:
            target: 扫描目标（用于文件命名）
            params: 必须包含 "state" 键，值为完整的状态字典

        Returns:
            {"output_path": str, "format": str}
        """
        state = (params or {}).get("state", {})
        output_format = (params or {}).get("format", "md")

        # 确保报告目录存在
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        # 生成文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace(":", "_").replace("/", "_") if target else "unknown"

        if output_format == "md":
            output_path = self._generate_markdown(state, safe_target, timestamp)
        elif output_format == "json":
            output_path = self._generate_json(state, safe_target, timestamp)
        else:
            output_path = self._generate_markdown(state, safe_target, timestamp)

        return {
            "output_path": str(output_path),
            "format": output_format,
            "target": target,
        }

    def _generate_markdown(self, state: dict, safe_target: str, timestamp: str) -> Path:
        """生成 Markdown 格式报告"""
        output_path = REPORTS_DIR / f"report_{safe_target}_{timestamp}.md"

        whois_info = state.get("whois_info", {})
        if not whois_info:
            whois_info = self._extract_whois_from_messages(state.get("messages", []))

        ip_domain_map = self._build_ip_domain_map(state)

        template = Template(MARKDOWN_TEMPLATE)
        content = template.render(
            target=state.get("target", ""),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            iteration=state.get("iteration", 0),
            whois_info=whois_info,
            subdomains=state.get("subdomains", []),
            open_ports=state.get("open_ports", []),
            ip_domain_map=ip_domain_map,
            has_cdn=state.get("has_cdn", False),
            has_waf=state.get("has_waf", False),
            real_ip=state.get("real_ip", ""),
            fingerprints=state.get("fingerprints", []),
            sensitive_paths=state.get("sensitive_paths", []),
            apis=state.get("apis", []),
            screenshots=state.get("screenshots", []),
            vuln_hints=state.get("vuln_hints", []),
            icp_info=state.get("icp_info", {}),
            leak_info=state.get("leak_info", []),
            errors=state.get("errors", []),
            messages=state.get("messages", []),
        )

        output_path.write_text(content, encoding="utf-8")
        return output_path

    def _build_ip_domain_map(self, state: dict) -> dict[str, list[str]]:
        """
        构建 IP-域名映射表

        从 open_ports、dns_records 和 subdomains 中提取域名和 IP 的对应关系
        """
        ip_domain_map: dict[str, list[str]] = {}

        def add_mapping(ip: str, domain: str):
            if ip not in ip_domain_map:
                ip_domain_map[ip] = []
            if domain and domain not in ip_domain_map[ip]:
                ip_domain_map[ip].append(domain)

        open_ports = state.get("open_ports", [])
        for port in open_ports:
            ip = port.get("ip")
            # 端口数据中可能包含 original_target 或 target 字段（用户输入的原始目标）
            host = port.get("original_target") or port.get("host") or port.get("target", "")
            # 提取 host 的纯域名/IP（去掉协议头和路径）
            if host:
                host = re.sub(r'^https?://', '', host, flags=re.IGNORECASE)
                host = host.split('/', 1)[0]
            if ip:
                add_mapping(ip, host)

        dns_records = state.get("dns_records", [])
        # 兼容两种格式：
        # 1. list[dict] 格式: [{"type": "A", "name": "x.com", "value": "1.2.3.4"}, ...]
        # 2. dict[str, list[str]] 格式: {"A": ["1.2.3.4"], "MX": ["mail.x.com"], ...}
        if isinstance(dns_records, dict):
            for rtype, values in dns_records.items():
                rtype_upper = str(rtype).upper()
                if rtype_upper in ("A", "AAAA"):
                    if isinstance(values, list):
                        for ip in values:
                            if ip:
                                add_mapping(str(ip), "")
        elif isinstance(dns_records, list):
            for record in dns_records:
                if not isinstance(record, dict):
                    continue
                record_type = record.get("type", "").upper()
                if record_type in ("A", "AAAA"):
                    ip = record.get("value", "")
                    name = record.get("name", "")
                    if ip:
                        add_mapping(ip, name)

        ips = state.get("ips", [])
        for ip in ips:
            if ip not in ip_domain_map:
                ip_domain_map[ip] = []

        return ip_domain_map

    def _generate_json(self, state: dict, safe_target: str, timestamp: str) -> Path:
        """生成 JSON 格式报告"""
        output_path = REPORTS_DIR / f"report_{safe_target}_{timestamp}.json"

        report_data = {
            "target": state.get("target", ""),
            "generated_at": datetime.now().isoformat(),
            "iteration": state.get("iteration", 0),
            "whois_info": state.get("whois_info", {}),
            "subdomains": state.get("subdomains", []),
            "open_ports": state.get("open_ports", []),
            "ips": state.get("ips", []),
            "dns_records": state.get("dns_records", []),
            "has_cdn": state.get("has_cdn", False),
            "has_waf": state.get("has_waf", False),
            "real_ip": state.get("real_ip", ""),
            "fingerprints": state.get("fingerprints", []),
            "sensitive_paths": state.get("sensitive_paths", []),
            "apis": state.get("apis", []),
            "screenshots": state.get("screenshots", []),
            "vuln_hints": state.get("vuln_hints", []),
            "icp_info": state.get("icp_info", {}),
            "leak_info": state.get("leak_info", []),
            "errors": state.get("errors", []),
            "messages": state.get("messages", []),
        }

        output_path.write_text(
            json.dumps(report_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return output_path

    def _extract_whois_from_messages(self, messages: list[str]) -> dict | None:
        """从 messages 中提取 WHOIS 信息（基础流程中 whois 结果存在 messages 里）"""
        whois_info = {}
        in_whois_block = False

        for msg in messages:
            if "[whois] 结果:" in msg:
                in_whois_block = True
                continue
            if in_whois_block and msg.startswith("  "):
                # 格式: "  key: value"
                parts = msg.strip().split(": ", 1)
                if len(parts) == 2:
                    whois_info[parts[0]] = parts[1]
            elif in_whois_block:
                in_whois_block = False

        return whois_info if whois_info else None