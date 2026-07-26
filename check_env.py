#!/usr/bin/env python3
"""
AI Recon Agent 环境一键检查脚本

检查内容：
1. Python 版本和环境
2. 外部命令行工具（nmap, subfinder, ffuf, playwright 等）
3. Python 依赖包
4. 注册工具实例化
5. 网络连通性（关键 API）
6. 环境变量配置
7. 目录权限
8. 向量库/数据库
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
from typing import Tuple, List, Dict

# 确保项目根目录在 Python 路径中
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

# 加载 .env 环境变量
from dotenv import load_dotenv
load_dotenv(ROOT_DIR / ".env")

# 颜色输出
COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "reset": "\033[0m",
}


def color_text(text: str, color: str) -> str:
    if platform.system() == "Windows":
        return text
    return f"{COLORS[color]}{text}{COLORS['reset']}"


def print_section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_result(name: str, status: bool, detail: str = ""):
    symbol = color_text("✓", "green") if status else color_text("✗", "red")
    status_str = color_text("OK", "green") if status else color_text("FAIL", "red")
    print(f"  {symbol} {name}: {status_str}")
    if detail:
        print(f"      {detail}")


def check_python() -> Tuple[bool, List[str]]:
    """检查 Python 版本和环境"""
    issues = []
    print_section("Python 环境检查")

    # Python 版本
    version = sys.version_info
    ok = version >= (3, 10)
    print_result(f"Python {version.major}.{version.minor}.{version.micro}", ok,
                f"要求 >= 3.10")
    if not ok:
        issues.append(f"Python 版本过低: {version.major}.{version.minor}.{version.micro}")

    # 虚拟环境
    venv = sys.prefix != sys.base_prefix
    print_result("虚拟环境", venv, "建议使用虚拟环境")

    # 路径检查
    paths = [p for p in sys.path if str(ROOT_DIR) in str(p)]
    print_result("项目路径", len(paths) > 0, f"根目录: {ROOT_DIR}")

    return len(issues) == 0, issues


def check_external_tools() -> Tuple[bool, List[str]]:
    """检查外部命令行工具"""
    issues = []
    print_section("外部命令行工具检查")

    tools = [
        ("nmap", "端口扫描工具", "-v"),
        ("subfinder", "子域名发现工具", "-version"),
        ("ffuf", "目录爆破工具", "-version"),
        ("playwright", "页面截图工具", "--version"),
    ]

    for name, desc, version_arg in tools:
        found, path, version = find_tool(name, version_arg)
        if found:
            print_result(f"{name} ({desc})", True, f"{path} v{version}")
        else:
            print_result(f"{name} ({desc})", False, f"未找到，请安装")
            issues.append(f"缺少工具: {name} ({desc})")

    return len(issues) == 0, issues


def find_tool(name: str, version_arg: str = "-v") -> Tuple[bool, str, str]:
    """查找工具是否存在"""
    cmd = ["where", name] if platform.system() == "Windows" else ["which", name]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            path = result.stdout.strip().split("\n")[0]
            # 尝试获取版本
            version = ""
            try:
                ver_result = subprocess.run(
                    [path, version_arg], capture_output=True, text=True, timeout=5
                )
                if ver_result.returncode == 0:
                    version = ver_result.stdout.strip()[:30]
            except Exception:
                pass
            return True, path, version
    except Exception:
        pass
    return False, "", ""


def check_python_dependencies() -> Tuple[bool, List[str]]:
    """检查 Python 依赖包"""
    issues = []
    print_section("Python 依赖包检查")

    dependencies = [
        ("langchain", ">=0.2.0"),
        ("langgraph", ">=0.1.0"),
        ("dotenv", ">=1.0.0", "python-dotenv"),
        ("pydantic", ">=2.0.0"),
        ("whois", ">=0.8.0", "python-whois"),
        ("dns", ">=2.0.0", "dnspython"),
        ("httpx", ">=0.24.0"),
        ("jinja2", ">=3.0.0"),
        ("chromadb", ">=0.4.0"),
    ]

    for item in dependencies:
        if len(item) == 3:
            import_name, min_version, pkg_name = item
        else:
            import_name, min_version = item
            pkg_name = import_name

        try:
            __import__(import_name)
            import importlib.metadata
            try:
                version = importlib.metadata.version(pkg_name)
            except importlib.metadata.PackageNotFoundError:
                version = "unknown"
            print_result(f"{pkg_name}", True, f"v{version} ({min_version})")
        except ImportError:
            print_result(f"{pkg_name}", False, f"未安装，要求 {min_version}")
            issues.append(f"缺少依赖: {pkg_name}")
        except Exception as e:
            print_result(f"{pkg_name}", False, f"错误: {e}")
            issues.append(f"依赖错误: {pkg_name}")

    return len(issues) == 0, issues


def check_registered_tools() -> Tuple[bool, List[str]]:
    """检查所有注册工具能否实例化"""
    issues = []
    print_section("注册工具检查")

    try:
        from tools.registry import list_tools, get_tool
    except ImportError as e:
        print_result("工具注册表", False, f"依赖缺失: {e}")
        issues.append(f"工具注册表依赖缺失: {e}")
        return False, issues

    try:
        tools = list_tools()
        print(f"  已注册工具: {len(tools)} 个")

        for name in tools:
            tool = get_tool(name)
            if tool:
                print_result(f"{name}", True,
                            f"is_passive={tool.is_passive}, timeout={tool.timeout}s")
            else:
                print_result(f"{name}", False, "获取失败")
                issues.append(f"工具注册失败: {name}")

    except Exception as e:
        print_result("工具注册表", False, f"加载失败: {e}")
        issues.append(f"工具注册表加载失败: {e}")

    return len(issues) == 0, issues


def check_network() -> Tuple[bool, List[str]]:
    """检查网络连通性"""
    issues = []
    print_section("网络连通性检查")

    try:
        import httpx
    except ImportError:
        print_result("httpx", False, "未安装，跳过网络检查")
        issues.append("httpx 未安装")
        return False, issues

    # 注意：GitHub API、crt.sh、Wayback 已有多 API 降级方案
    # 这里只检查基础连通性，不影响工具实际使用
    endpoints = [
        ("crt.sh", "https://crt.sh/", "证书日志 (有降级)"),
        ("GitHub API", "https://api.github.com/", "代码泄露检索 (有降级)"),
        ("Wayback Machine", "https://web.archive.org/", "历史归档 (有降级)"),
        ("ViewDNS", "https://viewdns.info/", "DNS 历史"),
        ("Finna API", "https://www.finna.com.cn/v1", "LLM 代理服务"),
    ]

    async def check_endpoint(name: str, url: str, desc: str):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, follow_redirects=True)
                if resp.status_code < 500:
                    print_result(f"{name} ({desc})", True, f"HTTP {resp.status_code}")
                else:
                    print_result(f"{name} ({desc})", False, f"HTTP {resp.status_code}")
                    issues.append(f"{name} 不可用")
        except Exception as e:
            print_result(f"{name} ({desc})", False, f"连接失败: {e}")
            issues.append(f"{name} 连接失败")

    import asyncio

    async def run_checks():
        await asyncio.gather(*[check_endpoint(n, u, d) for n, u, d in endpoints])

    asyncio.run(run_checks())

    return len(issues) == 0, issues


def check_env_vars() -> Tuple[bool, List[str]]:
    """检查环境变量配置"""
    issues = []
    print_section("环境变量检查")

    required = ["PLANNER_API_KEY", "VERIFY_API_BASE"]
    optional = ["DEEPSEEK_API_KEY", "OPENAI_API_KEY"]

    for key in required:
        value = os.environ.get(key, "")
        if value:
            print_result(key, True, f"已配置 ({len(value)} 字符)")
        else:
            print_result(key, False, "未配置")
            issues.append(f"缺少环境变量: {key}")

    for key in optional:
        value = os.environ.get(key, "")
        if value:
            print_result(key, True, f"已配置 ({len(value)} 字符)")
        else:
            print_result(key, False, "未配置（可选）")

    return len(issues) == 0, issues


def check_directories() -> Tuple[bool, List[str]]:
    """检查目录权限"""
    issues = []
    print_section("目录权限检查")

    from config.settings import DATA_DIR, CHROMA_DB_PATH, CACHE_DIR, LOGS_DIR, REPORTS_DIR, CHECKPOINTS_DIR

    dirs = [
        ("数据目录", DATA_DIR),
        ("向量库目录", CHROMA_DB_PATH),
        ("缓存目录", CACHE_DIR),
        ("日志目录", LOGS_DIR),
        ("报告目录", REPORTS_DIR),
        ("检查点目录", CHECKPOINTS_DIR),
    ]

    for name, path in dirs:
        try:
            path.mkdir(parents=True, exist_ok=True)
            test_file = path / ".test_write"
            test_file.write_text("test", encoding="utf-8")
            test_file.unlink()
            print_result(name, True, str(path))
        except PermissionError:
            print_result(name, False, f"权限不足: {path}")
            issues.append(f"目录权限不足: {path}")
        except Exception as e:
            print_result(name, False, f"错误: {e}")
            issues.append(f"目录错误: {path}")

    return len(issues) == 0, issues


def check_chromadb() -> Tuple[bool, List[str]]:
    """检查 Chroma 向量库"""
    issues = []
    print_section("向量库检查")

    try:
        import chromadb
    except ImportError:
        print_result("chromadb", False, "未安装，跳过向量库检查")
        issues.append("chromadb 未安装")
        return False, issues

    try:
        from knowledge.vector_store import get_vector_store

        vs = get_vector_store()
        count = vs._collection.count() if hasattr(vs, '_collection') else 0
        print_result("ChromaDB", True, f"已连接，文档数: {count}")
    except Exception as e:
        print_result("ChromaDB", False, f"初始化失败: {e}")
        issues.append(f"ChromaDB 初始化失败: {e}")

    return len(issues) == 0, issues


def check_startup() -> Tuple[bool, List[str]]:
    """运行启动自检"""
    issues = []
    print_section("启动自检")

    try:
        from utils.startup_check import run_startup_check
        result = run_startup_check(strict=False)
        print_result("启动自检", result, "全部通过" if result else "部分失败")
        if not result:
            issues.append("启动自检未完全通过")
    except Exception as e:
        print_result("启动自检", False, f"执行失败: {e}")
        issues.append(f"启动自检失败: {e}")

    return len(issues) == 0, issues


def main():
    """主函数"""
    print(f"\n{'#'*60}")
    print("#  AI Recon Agent 环境一键检查")
    print(f"#  时间: {platform.system()} {platform.release()}")
    print(f"#  Python: {sys.version.split()[0]}")
    print(f"#  项目: {ROOT_DIR}")
    print(f"{'#'*60}")

    all_issues = []
    checks = [
        check_python,
        check_env_vars,
        check_directories,
        check_python_dependencies,
        check_external_tools,
        check_registered_tools,
        check_network,
        check_chromadb,
        check_startup,
    ]

    for check in checks:
        ok, issues = check()
        all_issues.extend(issues)

    # 总结
    print(f"\n{'='*60}")
    print("  检查总结")
    print(f"{'='*60}")

    if not all_issues:
        print(color_text("  ✓ 所有检查通过！项目环境配置正确。", "green"))
    else:
        print(color_text(f"  ✗ 发现 {len(all_issues)} 个问题:", "red"))
        for i, issue in enumerate(all_issues, 1):
            print(f"    {i}. {issue}")
        print()
        print(color_text("  建议修复方案:", "yellow"))
        _generate_repair_suggestions(all_issues)

    return 0 if not all_issues else 1


def _generate_repair_suggestions(issues: list[str]):
    """根据实际问题动态生成修复建议"""
    suggestions = []
    missing_tools = []
    missing_deps = []
    missing_env_vars = []
    network_problems = []

    for issue in issues:
        if "缺少工具" in issue:
            # 提取工具名："缺少工具: subfinder (子域名发现工具)"
            tool_name = issue.replace("缺少工具: ", "").split(" ")[0]
            missing_tools.append(tool_name)
        elif "缺少依赖" in issue:
            dep_name = issue.replace("缺少依赖: ", "")
            missing_deps.append(dep_name)
        elif "缺少环境变量" in issue:
            var_name = issue.replace("缺少环境变量: ", "")
            missing_env_vars.append(var_name)
        elif "连接失败" in issue or "不可用" in issue:
            network_problems.append(issue)

    if missing_tools:
        suggestions.append(f"  [工具] 安装缺失工具: {'、'.join(missing_tools)}")
        suggestions.append(f"        winget install {' '.join(missing_tools)}")

    if missing_deps:
        suggestions.append(f"  [依赖] 安装缺失依赖: {'、'.join(missing_deps)}")
        suggestions.append("        pip install -r requirements.txt")

    if missing_env_vars:
        suggestions.append(f"  [配置] 配置环境变量: {'、'.join(missing_env_vars)}")
        suggestions.append("        编辑 .env 文件，添加相应的 API Key")

    if network_problems:
        suggestions.append("  [网络] 检查网络连通性")
        suggestions.append("        确保可以访问以下服务:")
        for np in network_problems[:3]:
            suggestions.append(f"          - {np}")

    # 添加通用建议
    if not suggestions:
        suggestions.append("  请根据上述问题逐一排查")

    for s in suggestions:
        print(s)


if __name__ == "__main__":
    sys.exit(main())
