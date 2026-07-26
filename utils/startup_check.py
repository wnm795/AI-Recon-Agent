# 启动前置自检工具模块
# 项目启动前自动校验：环境变量、外部工具、目录权限、依赖版本

import os
import sys
import shutil
from pathlib import Path
from typing import List

# 添加项目根目录到 Python 路径
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# 加载 .env 环境变量
from dotenv import load_dotenv
load_dotenv(ROOT_DIR / ".env")


class StartupCheckError(Exception):
    """启动检查失败异常"""
    pass


def check_env_vars(required_vars: List[str]) -> dict:
    """
    检查必需的环境变量是否存在
    
    Args:
        required_vars: 必需的环境变量名列表
        
    Returns:
        dict: 缺失的环境变量列表
        
    Raises:
        StartupCheckError: 缺少关键环境变量时抛出
    """
    missing_vars = []
    for var in required_vars:
        value = os.getenv(var, "")
        if not value or value.startswith("your_"):
            missing_vars.append(var)
    
    return {"missing": missing_vars, "status": len(missing_vars) == 0}


def check_external_tools(required_tools: List[str]) -> dict:
    """
    检查外部工具是否已安装
    
    Args:
        required_tools: 必需的工具名列表
        
    Returns:
        dict: 缺失的工具列表
    """
    missing_tools = []
    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    return {"missing": missing_tools, "status": len(missing_tools) == 0}


def check_directories(required_dirs: List[Path]) -> dict:
    """
    检查目录是否存在且可写
    
    Args:
        required_dirs: 必需的目录路径列表
        
    Returns:
        dict: 问题目录列表
    """
    problem_dirs = []
    for dir_path in required_dirs:
        if not dir_path.exists():
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                problem_dirs.append(f"{dir_path}: 创建失败 - {e}")
        elif not os.access(dir_path, os.W_OK):
            problem_dirs.append(f"{dir_path}: 无写入权限")
    
    return {"problems": problem_dirs, "status": len(problem_dirs) == 0}


def run_startup_check(strict: bool = True) -> bool:
    """
    执行完整的启动自检
    
    Args:
        strict: 严格模式，检查失败时抛出异常
        
    Returns:
        bool: 检查是否通过
        
    Raises:
        StartupCheckError: 严格模式下检查失败时抛出
    """
    errors = []
    
    # 1. 检查关键环境变量（Finna 代理配置）
    env_result = check_env_vars(["PLANNER_API_KEY", "VERIFY_API_BASE"])
    if not env_result["status"]:
        msg = f"缺少关键环境变量: {', '.join(env_result['missing'])}"
        errors.append(msg)
        if strict:
            raise StartupCheckError(msg)
    
    # 2. 检查核心目录
    from config.settings import DATA_DIR, CHROMA_DB_PATH, CACHE_DIR, LOGS_DIR, REPORTS_DIR, CHECKPOINTS_DIR
    
    dirs_result = check_directories([
        DATA_DIR, CHROMA_DB_PATH, CACHE_DIR, LOGS_DIR, REPORTS_DIR, CHECKPOINTS_DIR
    ])
    if not dirs_result["status"]:
        errors.append(f"目录问题: {', '.join(dirs_result['problems'])}")
    
    # 3. 可选：检查外部工具（非严格模式不阻塞）
    tools_result = check_external_tools(["nmap", "subfinder", "ffuf"])
    if not tools_result["status"]:
        print(f"[警告] 缺少外部工具: {', '.join(tools_result['missing'])}")
    
    # 输出检查结果
    if errors:
        print("[启动检查失败]")
        for err in errors:
            print(f"  - {err}")
        return False
    else:
        print("[启动检查通过] 环境配置正常")
        return True


def main():
    """命令行入口"""
    try:
        success = run_startup_check(strict=True)
        sys.exit(0 if success else 1)
    except StartupCheckError as e:
        print(f"[错误] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()