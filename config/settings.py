# 全局配置文件
# 集中管理所有全局参数：并发数、限流、超时、缓存 TTL、最大迭代次数等

import os
from pathlib import Path
from dotenv import load_dotenv

# 加载 .env 环境变量
load_dotenv()

# 项目根目录
BASE_DIR = Path(__file__).resolve().parent.parent

# ==================== LLM 配置 ====================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")

# 第三方 API 代理配置（Finna）
VERIFY_API_BASE = os.getenv("VERIFY_API_BASE", "")
PLANNER_API_KEY = os.getenv("PLANNER_API_KEY", "")
PLANNER_MODEL = os.getenv("PLANNER_MODEL", "deepseek-v4-pro")

# LLM 模型选择（可选 openai 或 deepseek）
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "deepseek")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")

# ==================== 并发与限流配置 ====================
# 被动工具最大并发数
MAX_CONCURRENT_PASSIVE_TOOLS = int(os.getenv("MAX_CONCURRENT_PASSIVE_TOOLS", "8"))

# 多资产并行扫描最大并发数（子域名/IP分支并发）
MAX_CONCURRENT_ASSETS = int(os.getenv("MAX_CONCURRENT_ASSETS", "5"))

# 单目标每秒请求频率限制
RATE_LIMIT_PER_SECOND = int(os.getenv("RATE_LIMIT_PER_SECOND", "10"))

# ==================== 超时配置 ====================
# 工具缓存 TTL（秒）
CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))

# 被动工具超时（秒）
PASSIVE_TOOL_TIMEOUT = int(os.getenv("PASSIVE_TOOL_TIMEOUT", "10"))

# 主动工具超时（秒）
ACTIVE_TOOL_TIMEOUT = int(os.getenv("ACTIVE_TOOL_TIMEOUT", "300"))

# ==================== 迭代配置 ====================
# 最大迭代次数
MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "30"))

# ==================== 路径配置 ====================
# 数据存储目录
DATA_DIR = BASE_DIR / "data"
CHROMA_DB_PATH = DATA_DIR / "chroma_db"
CACHE_DIR = DATA_DIR / "cache"
LOGS_DIR = DATA_DIR / "logs"
REPORTS_DIR = DATA_DIR / "reports"
CHECKPOINTS_DIR = DATA_DIR / "checkpoints"

# 知识库数据目录
KNOWLEDGE_DATA_DIR = BASE_DIR / "knowledge" / "data"

# ==================== 日志配置 ====================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")