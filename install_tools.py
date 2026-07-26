# 一键安装本地工具脚本
# 自动检测并安装 nmap、subfinder、ffuf（Windows 环境）
# 用法: python scripts/install_tools.py

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

# 项目根目录
ROOT_DIR = Path(__file__).resolve().parent.parent
BIN_DIR = ROOT_DIR / "tools" / "bin"

# 工具配置: 名称 -> 检测命令、下载地址、安装说明
TOOLS_CONFIG = {
    "nmap": {
        "check": ["nmap", "--version"],
        "windows": {
            "url": "https://nmap.org/dist/nmap-7.95-setup.exe",
            "filename": "nmap-7.95-setup.exe",
            "installer": True,
            "note": "请运行下载的 nmap-7.95-setup.exe 完成安装",
        },
        "fallback": "https://nmap.org/download.html",
    },
    "subfinder": {
        "check": ["subfinder", "-version"],
        "windows": {
            "url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_windows_amd64.zip",
            "filename": "subfinder.zip",
            "installer": False,
            "extract_name": "subfinder.exe",
        },
        "fallback": "https://github.com/projectdiscovery/subfinder/releases",
    },
    "ffuf": {
        "check": ["ffuf", "-V"],
        "windows": {
            "url": "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip",
            "filename": "ffuf.zip",
            "installer": False,
            "extract_name": "ffuf.exe",
        },
        "fallback": "https://github.com/ffuf/ffuf/releases",
    },
}


def print_banner():
    print("=" * 60)
    print("  AI Recon Agent - 本地工具一键安装脚本")
    print("  将自动检测并安装: nmap, subfinder, ffuf")
    print("=" * 60)
    print()


def is_tool_installed(tool_name: str) -> bool:
    """检测工具是否已安装并在 PATH 中"""
    return shutil.which(tool_name) is not None


def download_file(url: str, dest: Path) -> bool:
    """下载文件到指定路径"""
    try:
        print(f"  正在下载: {url}")
        print(f"  保存到: {dest}")
        urlretrieve(url, dest)
        print(f"  下载完成: {dest.stat().st_size / 1024:.1f} KB")
        return True
    except Exception as e:
        print(f"  下载失败: {e}")
        return False


def extract_zip(zip_path: Path, extract_dir: Path, target_name: str = None) -> Path | None:
    """解压 zip 文件，可选提取指定文件名"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            if target_name:
                # 查找目标文件
                for name in zf.namelist():
                    if name.endswith(target_name) or name == target_name:
                        zf.extract(name, extract_dir)
                        extracted = extract_dir / name
                        # 如果解压出来是子目录，移到根目录
                        final_path = extract_dir / target_name
                        if extracted != final_path:
                            extracted.rename(final_path)
                        return final_path
                print(f"  未在压缩包中找到 {target_name}")
                return None
            else:
                zf.extractall(extract_dir)
                return extract_dir
    except Exception as e:
        print(f"  解压失败: {e}")
        return None


def add_to_path(directory: Path) -> bool:
    """将目录添加到用户 PATH 环境变量（仅当前会话）"""
    try:
        current_path = os.environ.get("PATH", "")
        dir_str = str(directory.resolve())
        if dir_str not in current_path:
            os.environ["PATH"] = dir_str + os.pathsep + current_path
            print(f"  已临时添加到 PATH: {dir_str}")
        return True
    except Exception as e:
        print(f"  添加到 PATH 失败: {e}")
        return False


def install_tool_windows(tool_name: str, config: dict) -> bool:
    """在 Windows 上安装工具"""
    win_config = config.get("windows", {})
    if not win_config:
        print(f"  未找到 {tool_name} 的 Windows 安装配置")
        return False

    url = win_config.get("url")
    filename = win_config.get("filename", f"{tool_name}.zip")
    is_installer = win_config.get("installer", False)
    extract_name = win_config.get("extract_name")

    # 创建临时目录
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.gettempdir()) / "recon_agent_install"
    temp_dir.mkdir(exist_ok=True)

    download_path = temp_dir / filename

    # 下载
    if not download_file(url, download_path):
        return False

    if is_installer:
        # 安装程序（如 nmap setup.exe）
        print(f"  已下载安装程序: {download_path}")
        print(f"  请手动运行该安装程序完成安装")
        print(f"  按 Enter 继续...")
        input()
        return is_tool_installed(tool_name)
    else:
        # 压缩包，解压到项目 tools/bin 目录
        if filename.endswith(".zip"):
            extracted = extract_zip(download_path, BIN_DIR, extract_name)
            if extracted:
                print(f"  已解压到: {extracted}")
                # 添加到 PATH
                add_to_path(BIN_DIR)
                return is_tool_installed(tool_name)
        else:
            # 直接复制
            dest = BIN_DIR / (extract_name or filename)
            download_path.rename(dest)
            add_to_path(BIN_DIR)
            return is_tool_installed(tool_name)

    return False


def install_tool(tool_name: str, config: dict) -> bool:
    """安装指定工具（跨平台）"""
    print(f"\n[安装 {tool_name}]")

    if sys.platform == "win32":
        success = install_tool_windows(tool_name, config)
    else:
        print(f"  非 Windows 平台，请手动安装 {tool_name}")
        print(f"  参考: {config.get('fallback', '')}")
        success = False

    return success


def print_manual_guide():
    """打印手动安装指南"""
    print("\n" + "=" * 60)
    print("  手动安装指南")
    print("=" * 60)
    print()
    print("如果自动安装失败，请手动安装以下工具：")
    print()
    print("1. Nmap (端口扫描)")
    print("   下载: https://nmap.org/download.html")
    print("   安装: 运行下载的 .exe 安装程序")
    print("   验证: nmap --version")
    print()
    print("2. Subfinder (子域名枚举)")
    print("   下载: https://github.com/projectdiscovery/subfinder/releases")
    print("   选择: subfinder_*_windows_amd64.zip")
    print("   安装: 解压后将 subfinder.exe 放到 PATH 中的目录")
    print("   验证: subfinder -version")
    print()
    print("3. ffuf (目录爆破)")
    print("   下载: https://github.com/ffuf/ffuf/releases")
    print("   选择: ffuf_*_windows_amd64.zip")
    print("   安装: 解压后将 ffuf.exe 放到 PATH 中的目录")
    print("   验证: ffuf -V")
    print()
    print("建议: 将工具统一放在项目 tools/bin 目录下")
    print(f"      路径: {BIN_DIR}")
    print()


def main():
    print_banner()

    # 检查当前状态
    missing_tools = []
    installed_tools = []

    for tool_name, config in TOOLS_CONFIG.items():
        if is_tool_installed(tool_name):
            print(f"[✓] {tool_name}: 已安装")
            installed_tools.append(tool_name)
        else:
            print(f"[✗] {tool_name}: 未安装")
            missing_tools.append(tool_name)

    if not missing_tools:
        print("\n[全部工具已安装] 无需额外操作")
        return 0

    print(f"\n发现 {len(missing_tools)} 个工具需要安装: {', '.join(missing_tools)}")
    print()

    # 询问是否自动安装
    if len(sys.argv) > 1 and sys.argv[1] == "--auto":
        confirm = "y"
    else:
        confirm = input("是否尝试自动安装？(y/n): ").strip().lower()

    if confirm != "y":
        print_manual_guide()
        return 0

    # 自动安装
    failed_tools = []
    for tool_name in missing_tools:
        config = TOOLS_CONFIG[tool_name]
        if install_tool(tool_name, config):
            print(f"[✓] {tool_name}: 安装成功")
            installed_tools.append(tool_name)
        else:
            print(f"[✗] {tool_name}: 安装失败")
            failed_tools.append(tool_name)

    # 最终报告
    print("\n" + "=" * 60)
    print("  安装结果")
    print("=" * 60)
    print(f"已安装: {', '.join(installed_tools) if installed_tools else '无'}")
    if failed_tools:
        print(f"失败: {', '.join(failed_tools)}")
        print()
        print_manual_guide()
        return 1
    else:
        print("\n[全部安装完成]")
        return 0


if __name__ == "__main__":
    sys.exit(main())
