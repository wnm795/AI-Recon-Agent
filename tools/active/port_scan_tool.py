# 端口扫描工具
# 基于 python-nmap 进行端口与服务扫描，最长 120s 超时

import asyncio
import re
import subprocess
from typing import Any

from tools.base import BaseTool


class PortScanTool(BaseTool):
    """
    端口扫描工具

    调用 nmap 进行端口与服务发现
    使用 -oG 格式化输出便于解析
    """

    tool_name = "portscan"
    description = "端口与服务扫描，基于 nmap"
    timeout = 120
    max_retries = 1
    cache_ttl = 3600
    is_passive = False

    # 默认扫描参数
    DEFAULT_ARGS = ["-sS", "-F", "-T4"]

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        执行端口扫描

        Args:
            target: 目标 IP 或域名
            params: 可选参数
                - ports: 指定端口范围，如 "1-1000"
                - scan_args: nmap 额外参数列表

        Returns:
            {"host": target, "open_ports": [{port, service, state}]}
        """
        scan_args = (params or {}).get("scan_args", self.DEFAULT_ARGS)
        ports = (params or {}).get("ports", None)

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            self._run_nmap_sync,
            target,
            scan_args,
            ports,
        )
        return result

    def _run_nmap_sync(self, target: str, scan_args: list, ports: str | None) -> dict[str, Any]:
        """同步执行 nmap 扫描（在线程池中调用）"""
        # nmap 不接受 URL 形式（如 http://10.11.120.141），需要剥掉协议头
        nmap_target = self._strip_url_scheme(target)
        if not nmap_target:
            return {
                "host": target,
                "target": target,
                "open_ports": [],
                "count": 0,
                "raw_args": "",
                "error": f"无法从目标中提取有效的 IP/域名: {target!r}",
            }

        # 构建命令
        cmd = ["nmap"] + scan_args + ["-oG", "-", nmap_target]
        if ports:
            cmd = ["nmap"] + scan_args + ["-p", ports, "-oG", "-", nmap_target]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                encoding="utf-8",
                errors="replace",
            )

            open_ports = []
            host_ip = nmap_target

            if proc.stdout:
                open_ports, host_ip = self._parse_grepable_output(proc.stdout, nmap_target)

            return {
                "host": host_ip,
                "target": nmap_target,
                "original_target": target,
                "open_ports": open_ports,
                "count": len(open_ports),
                "raw_args": " ".join(cmd),
            }

        except subprocess.TimeoutExpired:
            raise TimeoutError(f"nmap 扫描超时（{self.timeout}s）")
        except FileNotFoundError:
            raise RuntimeError("nmap 未安装或不在 PATH 中")

    @staticmethod
    def _strip_url_scheme(target: str) -> str:
        """
        剥离 URL 协议头和路径，提取纯 IP/域名

        处理场景：
        - "http://10.11.120.141/pkc/" -> "10.11.120.141"
        - "https://www.example.com/path" -> "www.example.com"
        - "10.11.120.141" -> "10.11.120.141"
        - "www.example.com" -> "www.example.com"
        """
        import re
        if not target:
            return ""

        text = str(target).strip()

        # 去除协议头
        text = re.sub(r'^https?://', '', text, flags=re.IGNORECASE)

        # 去除路径
        text = text.split('/', 1)[0]

        # 去除端口
        text = text.split(':', 1)[0]

        return text.strip()

    def _parse_grepable_output(self, output: str, target: str) -> tuple[list[dict], str]:
        """
        解析 nmap -oG 格式化输出

        -oG 输出示例行:
        Host: 192.168.1.1 (host.local)	Ports: 22/open/tcp//ssh//OpenSSH 7.6/, 80/open/tcp//http//nginx 1.14/

        Returns:
            (open_ports, host_ip)
        """
        open_ports = []
        host_ip = target

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # 提取 Host 行
            if line.startswith("Host:"):
                # 解析 Host 字段
                host_match = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
                if host_match:
                    host_ip = host_match.group(1)

                # 解析 Ports 字段
                ports_match = re.search(r"Ports:\s+(.+)", line)
                if ports_match:
                    ports_str = ports_match.group(1)
                    for port_entry in ports_str.split(","):
                        port_entry = port_entry.strip()
                        if not port_entry:
                            continue
                        # 格式: port/state/proto//service//version/
                        parts = port_entry.split("/")
                        if len(parts) >= 5 and parts[1] == "open":
                            open_ports.append({
                                "ip": host_ip,
                                "port": int(parts[0]),
                                "state": parts[1],
                                "protocol": parts[2],
                                "service": parts[4] if len(parts) > 4 else "unknown",
                            })

        return open_ports, host_ip