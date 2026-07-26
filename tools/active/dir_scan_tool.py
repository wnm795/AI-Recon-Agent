# 敏感目录爆破工具
# 基于 ffuf 分级字典敏感目录爆破，支持限流配置
# 工具入口具备 URL 自适应能力：从任意输入中提取并校验合法 URL

import asyncio
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from tools.base import BaseTool


# URL 自适应提取：从中英文混合/标点污染的输入中提取合法 URL
URL_REGEX = re.compile(
    r'(?:(?:https?|ftp)://)?'                                 # 可选协议头
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'  # 域名
    r'[a-zA-Z]{2,}'                                           # 顶级域
    r'(?::\d{1,5})?'                                          # 可选端口
    r'(?:/[^\s\x00-\x1f\x7f`"\'<>\\^|]*)?',                   # 可选路径（过滤控制字符、反引号、引号等）
    re.IGNORECASE
)

# 非法字符检测（中文字符、引号、反引号等）
ILLEGAL_CHARS = re.compile(r'[^\x00-\x7f`"\'<>\\^|{}\s]')


def extract_clean_url(raw_input: str) -> str:
    """
    从任意输入中提取并清洗为合法 URL

    处理场景：
    - "帮我爆破目录https://www.hesaitech.com/" -> "https://www.hesaitech.com"
    - "扫描 www.baidu.com 的子域名" -> "http://www.baidu.com"
    - "https://www.hesaitech.com/的目录" -> "https://www.hesaitech.com"（自动剥离尾部中文）
    - "192.168.1.1" -> "http://192.168.1.1"
    """
    if not raw_input:
        return ""

    text = str(raw_input).strip()

    # 1. 优先匹配完整 URL（带协议）
    https_match = re.search(r'https?://[^\s\x00-\x1f\x7f`"\'<>\\^|]*', text, re.IGNORECASE)
    if https_match:
        candidate = https_match.group(0)
    else:
        # 2. 匹配裸域名/IP
        domain_match = re.search(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            r'(?::\d{1,5})?(?:/[^\s\x00-\x1f\x7f`"\'<>\\^|,;]*)?',
            text
        )
        ip_match = re.search(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b(?::\d{1,5})?',
            text
        )
        candidate = ""
        if domain_match:
            candidate = domain_match.group(0)
        elif ip_match:
            candidate = ip_match.group(0)

    if not candidate:
        return ""

    # 3. 清理非法字符（中文字符、引号、反引号、逗号、分号、尖括号等）
    candidate = ILLEGAL_CHARS.sub('', candidate).strip()
    # 去除尾部所有非 URL 合法字符（保留 / : . - _ ~ ! ? # [ ] @ $ & ' ( ) * + , ; = 等合法符号）
    candidate = re.sub(r'[`"\'<>\\^|{}\s,;]+$', '', candidate)

    # 4. 补全协议头
    if not candidate.startswith(('http://', 'https://')):
        candidate = f"http://{candidate}"

    # 5. 校验 URL 合法性
    try:
        parsed = urlparse(candidate)
        if not parsed.netloc or '.' not in parsed.netloc:
            return ""
        # 去除路径中可能的非法残留
        clean_path = re.sub(r'[^\x00-\x7f`"\'<>\\^|{}\s/]', '', parsed.path or '')
        # 再次清理路径末尾的非法符号
        clean_path = re.sub(r'[`"\'<>\\^|{}\s,;]+$', '', clean_path)
        return f"{parsed.scheme}://{parsed.netloc}{clean_path}".rstrip('/')
    except Exception:
        return ""


def validate_url(url: str) -> tuple[bool, str]:
    """
    校验 URL 合法性
    Returns: (is_valid, error_message)
    """
    if not url:
        return False, "URL 为空"
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False, f"不支持的协议: {parsed.scheme}"
        if not parsed.netloc:
            return False, "缺少域名"
        return True, ""
    except Exception as e:
        return False, f"URL 解析失败: {e}"


class DirScanTool(BaseTool):
    """
    敏感目录爆破工具

    调用 ffuf 进行目录爆破，自动分级加载字典
    ffuf 不可用时降级到内置常见路径列表
    工具入口自动从任意输入中提取并校验合法 URL
    """

    tool_name = "dir_scan"
    description = "敏感目录/文件爆破"
    timeout = 300  # 目录爆破需要更长时间（48114 个路径约需 50-60s）
    max_retries = 0  # 禁用重试，避免重复扫描浪费时间
    cache_ttl = 0  # 目录爆破结果可能变化（路径新增/删除/WAF 拦截状态变化），不缓存避免误导用户
    is_passive = False

    # 字典文件路径：统一从同级目录的 DIR.txt 加载
    _DICT_FILE = Path(__file__).parent / "DIR.txt"

    @classmethod
    def _load_wordlist(cls) -> list[str]:
        """
        从同级目录的 DIR.txt 加载字典

        优先级：
        1. DIR.txt（用户自定义字典，一行一个路径）
        2. 内置 COMMON_PATHS（DIR.txt 不存在或为空时使用）

        编码兼容：自动尝试 utf-8、utf-8-sig、gbk、gb18030
        """
        if not cls._DICT_FILE.exists():
            return cls.COMMON_PATHS

        # 尝试多种编码
        encodings = ["utf-8", "utf-8-sig", "gbk", "gb18030", "latin-1"]
        content = None
        for enc in encodings:
            try:
                with open(cls._DICT_FILE, "r", encoding=enc) as f:
                    content = f.read()
                break
            except (UnicodeDecodeError, LookupError):
                continue

        if content is None:
            print(f"[dir_scan] 字典文件编码无法识别，使用内置字典")
            return cls.COMMON_PATHS

        paths = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
        if not paths:
            return cls.COMMON_PATHS

        print(f"[dir_scan] 已从 DIR.txt 加载 {len(paths)} 个路径")
        return paths

    # 内置常见敏感路径（ffuf 不可用时使用，也作为 DIR.txt 缺失时的兜底）
    COMMON_PATHS = [
        # 常见管理后台
        "/admin", "/login", "/manager", "/management", "/console",
        # API 端点
        "/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/swagger-ui.html",
        "/swagger.json", "/openapi.json", "/api-docs", "/docs",
        # 备份文件
        "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
        "/dump.sql", "/www.zip", "/site.zip", "/web.zip", "/src.zip",
        # 配置文件
        "/config", "/config.php", "/config.yml", "/config.yaml", "/config.json",
        "/settings.php", "/settings.json", "/.env", "/.env.local", "/.env.production",
        # 版本控制
        "/.git", "/.git/config", "/.git/HEAD", "/.gitignore",
        "/.svn", "/.svn/entries", "/.hg",
        # CMS 系统
        "/wp-admin", "/wp-login.php", "/wp-config.php",
        "/phpmyadmin", "/pma", "/adminer", "/adminer.php",
        "/joomla/administrator", "/drupal", "/drupal/login",
        # 框架
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/beans",
        "/actuator/mappings", "/api/actuator",
        # 测试/开发
        "/test", "/dev", "/staging", "/debug", "/debug.log",
        "/debug/default/view", "/elmah.axd", "/trace.axd",
        # 服务器状态
        "/server-status", "/server-info", "/status", "/health", "/healthcheck",
        # 其他敏感路径
        "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
        "/.htaccess", "/.htpasswd", "/web.config", "/crossdomain.xml",
        "/phpinfo.php", "/info.php", "/test.php",
        # 上传目录
        "/upload", "/uploads", "/files", "/media", "/static",
        # 用户
        "/user", "/users", "/account", "/profile", "/member",
        # 日志
        "/logs", "/log", "/error.log", "/access.log",
    ]

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行目录爆破"""
        # 工具自防御：自行从任意输入中提取并校验合法 URL
        clean_url = extract_clean_url(target)
        is_valid, error_msg = validate_url(clean_url)

        if not is_valid:
            return {
                "target": target,
                "url": "",
                "sensitive_paths": [],
                "count": 0,
                "source": "input_validation",
                "error": f"目标解析失败: {error_msg}，原始输入: {target!r}",
            }

        # 检查 ffuf 是否可用
        import shutil
        if shutil.which("ffuf"):
            return await self._run_ffuf(clean_url, params)
        else:
            return await self._run_builtin(clean_url)

    async def _run_ffuf(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        使用 ffuf 进行目录爆破

        支持参数 (通过 params 传入):
            - extensions: 扩展名列表，如 [".php", ".html", ".bak"]
            - threads: 并发线程数 (默认 20)
            - timeout: HTTP 请求超时 (默认 10)
            - follow_redirects: 是否跟随重定向 (默认 False)
            - match_codes: 匹配的状态码 (默认 "200,204,301,302,401,403,405,500")
            - filter_size: 过滤响应大小
            - filter_words: 过滤响应词数
            - filter_lines: 过滤响应行数
            - rate: 每秒请求数限制
            - recursion: 是否递归扫描 (默认 False)
            - recursion_depth: 递归深度 (默认 2)
            - headers: 自定义请求头列表，如 ["Cookie: xxx", "Authorization: Bearer xxx"]
            - method: HTTP 方法 (默认 GET)
            - post_data: POST 数据
            - proxy: 代理地址
            - output_format: 输出格式 (json/ejson/csv)
        """
        loop = asyncio.get_event_loop()
        params = params or {}

        # 构建命令
        import os
        is_windows = os.name == 'nt'
        
        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-t", str(params.get("threads", 20)),
            "-timeout", str(params.get("timeout", 10)),
        ]
        
        # 字典输入：统一从同级目录的 DIR.txt 加载（Windows/Linux 都使用临时文件）
        import tempfile
        wordlist = self._load_wordlist()
        stdin_text = "\n".join(wordlist)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(stdin_text)
            wordlist_file = f.name
        cmd.extend(["-w", wordlist_file])

        # HTTP 方法
        if params.get("method") and params["method"].upper() != "GET":
            cmd.extend(["-X", params["method"]])

        # POST 数据
        if params.get("post_data"):
            cmd.extend(["-d", params["post_data"]])

        # 自定义请求头
        for header in params.get("headers", []):
            cmd.extend(["-H", header])

        # 跟随重定向
        if params.get("follow_redirects", False):
            cmd.append("-r")

        # 代理
        if params.get("proxy"):
            cmd.extend(["-x", params["proxy"]])

        # 匹配状态码
        match_codes = params.get("match_codes", "200,204,301,302,401,403,405,500")
        cmd.extend(["-mc", match_codes])

        # 过滤条件
        if params.get("filter_size"):
            cmd.extend(["-fs", str(params["filter_size"])])
        if params.get("filter_words"):
            cmd.extend(["-fw", str(params["filter_words"])])
        if params.get("filter_lines"):
            cmd.extend(["-fl", str(params["filter_lines"])])

        # 速率限制
        if params.get("rate"):
            cmd.extend(["-rate", str(params["rate"])])

        # 递归扫描
        if params.get("recursion", False):
            cmd.append("-recursion")
            cmd.extend(["-recursion-depth", str(params.get("recursion_depth", 2))])

        # 扩展名
        extensions = params.get("extensions", [])
        if extensions:
            cmd.extend(["-e", ",".join(extensions)])

        # 输出格式：控制台 JSON 输出（-json），文件输出（-o + -of）
        cmd.append("-json")  # 控制台输出 JSON 格式（便于解析）

        # 静默模式（仅输出结果）
        cmd.append("-s")

        try:
            # 内层 subprocess 超时 = 外层 asyncio.wait_for 超时 - 5秒（缓冲）
            inner_timeout = max(self.timeout - 5, 10)
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=inner_timeout,
                )
            )
            # 清理临时字典文件
            try:
                os.unlink(wordlist_file)
            except OSError:
                pass

            # 手动解码 stdout/stderr，避免 Windows GBK 编码问题
            stdout_text = self._safe_decode(proc.stdout)
            stderr_text = self._safe_decode(proc.stderr)

            if proc.returncode != 0 and not stdout_text:
                print(f"[dir_scan] ffuf 执行失败 (返回码 {proc.returncode}): {stderr_text[:500]}")

            found = self._parse_ffuf_output(stdout_text, url)

            return {
                "target": url,
                "sensitive_paths": found,
                "count": len(found),
                "source": "ffuf",
                "config": {
                    "threads": params.get("threads", 20),
                    "match_codes": match_codes,
                    "extensions": extensions,
                    "recursion": params.get("recursion", False),
                },
            }
        except subprocess.TimeoutExpired:
            return {
                "target": url,
                "sensitive_paths": [],
                "count": 0,
                "source": "ffuf",
                "error": f"ffuf 执行超时（{self.timeout}s）",
            }
        except Exception as e:
            return await self._run_builtin(url)

    def _safe_decode(self, data: bytes) -> str:
        """安全解码 bytes 数据，避免 Windows GBK 编码问题"""
        if not data:
            return ""
        if isinstance(data, str):
            return data

        # 尝试多种编码
        for enc in ["utf-8", "gbk", "gb18030", "latin-1"]:
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        # 最后兜底：忽略错误
        return data.decode("utf-8", errors="ignore")

    def _parse_ffuf_output(self, output: str, base_url: str) -> list[dict]:
        """解析 ffuf JSON 输出（-json 格式）"""
        import json
        import base64
        import re

        found = []

        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # ffuf 2.1.0 的 JSON 输出中，FUZZ 字段可能是 Base64 编码
                fuzz_encoded = obj.get("input", {}).get("FUZZ", "")
                if fuzz_encoded:
                    # 尝试 Base64 解码（如果失败则直接使用原值）
                    try:
                        fuzz_value = base64.b64decode(fuzz_encoded).decode('utf-8')
                    except Exception:
                        fuzz_value = fuzz_encoded

                    # 清理 fuzz_value 前导斜杠，避免双斜杠
                    fuzz_value = fuzz_value.lstrip('/')

                    # 统一从 fuzz_value + base_url 构造最终 URL（避免 ffuf 在不同平台返回不一致的 URL 格式）
                    # base_url 已经是清理过末尾 / 的，所以拼接时只需要补一个 /
                    if base_url.endswith('/'):
                        final_url = f"{base_url}{fuzz_value}"
                    else:
                        final_url = f"{base_url}/{fuzz_value}"

                    # 最后防御：清理所有双斜杠（除了协议头的 http://）
                    final_url = re.sub(r'(?<!:)//+', '/', final_url)

                    found.append({
                        "url": final_url,
                        "path": f"/{fuzz_value}",
                        "status": obj.get("status"),
                        "length": obj.get("length"),
                        "words": obj.get("words"),
                        "lines": obj.get("lines"),
                        "content_type": obj.get("content-type", ""),
                    })
            except (json.JSONDecodeError, ValueError):
                continue

        return found

    async def _run_builtin(self, url: str) -> dict[str, Any]:
        """使用内置路径列表 + httpx 检查"""
        import httpx

        wordlist = self._load_wordlist()
        found = []
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            for path in wordlist:
                try:
                    resp = await client.get(f"{url}{path}")
                    if resp.status_code in (200, 204, 301, 302, 401, 403):
                        found.append({
                            "url": f"{url}{path}",
                            "path": path,
                            "status": str(resp.status_code),
                        })
                except Exception:
                    continue

        return {
            "target": url,
            "sensitive_paths": found,
            "count": len(found),
            "source": "builtin",
        }
