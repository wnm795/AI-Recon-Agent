# AI 渗透测试信息收集 Agent 完整架构设计文档（精简重构版）

构建**智能规划、并发执行、自我反思**的自动化信息收集 Agent，基于 LangGraph 状态驱动工作流；分层设计工具统一契约、带缓存 / 超时 / 重试容灾；内置可自更新 CVE 指纹向量知识库，明确本地规则与向量库分工；新增工具注册工厂、状态更新规约、CDN 专属分支、并发配置、启动自检能力；支持 CLI 启动、API 调用、结构化日志、多格式报告，纯本地实验场景。

## 1. 整体核心设计思路

1. **状态驱动调度**：`ReconState` 作为全局唯一数据载体，明确字段更新规则（reducer 追加 / 直接覆盖），全节点标准化读写状态流转，不靠硬编码顺序；全局资产集合自动去重，根据新资产判断是否迭代扫描。

2. **LLM 动态任务规划 + 工具注册解耦**：大模型根据当前资产、Web 指纹、CDN 状态动态生成差异化扫描任务；通过工具注册表统一映射任务名与工具实例，LLM 异常时自动降级基础扫描模板。

3. **双层并发执行 + 限流可控**：阶段内被动工具并发、多资产分支并发双模式，支持自定义最大并发数、请求频率限制；单工具独立超时隔离，局部失败不阻塞整体流程。

4. **标准化工具契约 + 分类完整**：补全分析类工具目录，全部工具统一入参出参，内置缓存 TTL、超时、指数退避重试，统一错误收集与恢复节点。

5. **分层 RAG 知识库（精准 + 模糊双匹配）**：区分本地指纹规则精准匹配、向量库语义模糊检索；Chroma 强制配置 Embedding，使用本地 sentence-transformers 离线模型；NVD API 定期同步最新 CVE。

6. **完整工程化能力**：结构化分层日志、单元 + 集成测试、FastAPI 对外接口、CLI 命令行启动、启动前置配置自检、多格式报告导出。

## 2. 项目目录结构

```
ai-recon-agent/
├── .env
├── .env.example                 # 环境变量模板
├── requirements.txt             # pip 依赖管理
├── README.md
│
├── config/                      # 全局配置目录
│   ├── settings.py              # 全局参数、并发数、限流、超时、缓存 TTL
│   └── prompts.py               # LLM 规划、分析阶段提示词
│
├── tools/                       # 标准化工具层，统一执行契约
│   ├── __init__.py
│   ├── base.py                  # 工具基类：缓存、超时、重试统一封装
│   ├── result_model.py          # ToolResult 统一返回数据模型
│   ├── registry.py              # 工具注册表/工厂，任务名与工具映射
│   │
│   ├── passive/                 # 无痕被动收集工具
│   │   ├── whois_tool.py
│   │   ├── dns_enum_tool.py
│   │   ├── subdomain_tool.py
│   │   ├── icp_tool.py
│   │   ├── github_leak_tool.py
│   │   ├── wayback_tool.py
│   │   └── cert_log_tool.py
│   │
│   ├── active/                  # 主动发包扫描工具
│   │   ├── cdn_detect_tool.py
│   │   ├── cdn_bypass_tool.py
│   │   ├── port_scan_tool.py
│   │   ├── http_fingerprint.py
│   │   ├── dir_scan_tool.py
│   │   ├── api_discover.py
│   │   └── screenshot_tool.py
│   │
│   └── analysis/                # 分析类工具目录
│       ├── vuln_match_tool.py   # 基于 RAG 的 CVE 漏洞匹配
│       └── report_tool.py       # 多格式报告生成工具
│
├── workflow/                    # LangGraph 核心工作流
│   ├── state.py                 # 全局 ReconState 状态定义（含更新规约）
│   ├── graph.py                 # 图构建、条件分支、CDN 专属分支、节点串联
│   └── nodes/                   # 拆分独立功能节点
│       ├── plan_node.py         # LLM 动态任务规划节点
│       ├── passive_node.py      # 并发执行被动工具
│       ├── active_node.py       # 多资产并行扫描
│       ├── error_handler_node.py # 错误重试/跳过决策
│       ├── reflect_node.py      # 资产去重、迭代终止判断
│       ├── analyze_node.py      # 指纹匹配、漏洞 RAG 检索
│       └── report_node.py       # 多格式报告生成
│
├── knowledge/                   # RAG 向量知识库层
│   ├── __init__.py
│   ├── vector_store.py          # Chroma 封装，强制注入 Embedding
│   ├── loaders/                 # 数据加载与同步脚本
│   │   ├── cve_loader.py        # CVE 解析、向量库写入与查询
│   │   ├── nvd_sync.py          # NVD API 增量同步 CVE
│   │   ├── fingerprint_loader.py
│   │   └── port_service_loader.py
│   └── data/                    # 静态原始规则文件
│       ├── fingerprint_db.json
│       └── port_services.json
│
├── data/                        # 持久化存储目录
│   ├── chroma_db/               # 向量库持久文件
│   ├── checkpoints/             # LangGraph 检查点（断点续跑）
│   ├── cache/                   # 工具缓存，带 TTL 过期清理
│   ├── logs/                    # 结构化 JSON 日志，分阶段存放
│   └── reports/                 # md/json/csv 扫描报告
│
├── utils/
│   ├── logger.py                # 结构化日志工具
│   ├── validators.py            # 域名/IP 格式校验
│   ├── rate_limiter.py          # 请求限流防封禁
│   ├── cache_helper.py          # 文件缓存读写、过期清理
│   └── startup_check.py         # 启动前置自检工具
│
├── api/                         # FastAPI 对外接口层
│   └── main.py                  # 启动扫描、查询进度、下载报告接口
│
├── tests/                       # 全套测试体系
│   ├── __init__.py
│   ├── test_state_and_tool.py
│   ├── test_whois_tool.py
│   ├── test_graph.py
│   └── test_full_workflow.py
│
├── scripts/                     # 辅助定时脚本
│   └── sync_cve_task.py         # 定时同步 NVD 漏洞数据
│
└── main.py                      # CLI 命令行入口
```

## 3. 完整工具体系

### 3.1 被动信息收集工具

| 工具名称 | 任务名 | 核心功能 | 底层依赖 |
|---------|--------|---------|---------|
| whois_tool | whois | 域名注册信息查询 | python-whois |
| dns_enum_tool | dns_enum | 全类型 DNS 记录枚举 | dnspython |
| subdomain_tool | subdomain | 子域名批量挖掘 | subfinder + crt.sh + hackertarget + threatcrowd + certspotter |
| icp_tool | icp | 企业备案信息抓取 | httpx |
| github_leak_tool | github_leak | 代码仓库配置泄露检索 | httpx |
| wayback_tool | wayback | 历史归档页面爬取 | httpx |
| cert_log_tool | cert_log | 证书日志挖掘子域名 | crt.sh API |

### 3.2 主动信息收集工具

| 工具名称 | 任务名 | 核心功能 | 底层依赖 |
|---------|--------|---------|---------|
| cdn_detect_tool | cdn_detect | CDN/WAF 识别 | httpx |
| cdn_bypass_tool | cdn_bypass | CDN 真实 IP 挖掘 | 多源 IP 交叉比对 |
| port_scan_tool | portscan | 端口 & 服务扫描 | nmap |
| http_fingerprint | http_fingerprint | 多维度 Web 指纹识别 | httpx |
| dir_scan_tool | dir_scan | 敏感目录爆破 | ffuf |
| api_discover | api_discover | 页面 JS 接口提取 | httpx + beautifulsoup4 |
| screenshot_tool | screenshot | 页面无头截图 | playwright |

### 3.3 分析类工具

| 工具名称 | 任务名 | 功能 | 实现方式 |
|---------|--------|------|---------|
| vuln_match_tool | vuln_match | 组件版本匹配 CVE 漏洞 | Chroma 向量库 RAG 检索 + CPE 版本范围过滤 |
| report_tool | report_generator | 整合全量扫描数据输出报告 | Jinja2 模板渲染，支持 md/json/csv |

## 4. 工具统一标准契约

### 4.1 统一返回模型 ToolResult

```python
class ToolResult:
    success: bool
    data: Any | None
    error: str | None
    elapsed: float
    target: str
    tool_name: str
    from_cache: bool
```

### 4.2 基类统一入口 async execute(target, params)

- 优先读取 TTL 缓存，命中直接返回
- 未命中则循环重试（指数退避间隔）
- 单工具独立超时，超时抛出错误
- 执行成功写入缓存，失败记录错误
- 支持 `skip_cache=True` 跳过缓存

### 4.3 工具注册表

```python
# tools/registry.py
from tools.passive import *
from tools.active import *
from tools.analysis import *

TOOL_REGISTRY = {
    # 被动工具
    "whois": WhoisTool(),
    "dns_enum": DnsEnumTool(),
    "subdomain": SubdomainTool(),
    "icp": IcpTool(),
    "github_leak": GithubLeakTool(),
    "wayback": WaybackTool(),
    "cert_log": CertLogTool(),
    # 主动工具
    "cdn_detect": CdnDetectTool(),
    "cdn_bypass": CdnBypassTool(),
    "portscan": PortScanTool(),
    "http_fingerprint": HttpFingerprintTool(),
    "dir_scan": DirScanTool(),
    "api_discover": ApiDiscoverTool(),
    "screenshot": ScreenshotTool(),
    # 分析工具
    "vuln_match": VulnMatchTool(),
    "report_generator": ReportTool(),
}

def get_tool(tool_name: str) -> Optional[BaseTool]:
    return TOOL_REGISTRY.get(tool_name)
```

调用逻辑：plan_node 生成任务名称列表 → 执行节点遍历任务名 → 调用 `get_tool()` 获取实例 → 统一 execute 执行。

## 5. LangGraph 工作流核心设计

### 5.1 ReconState 全局状态

LangGraph 默认规则：无 reducer 字段会整体覆盖，配置 reducer 可增量追加。

- **reducer 追加**：messages、completed_tasks、errors、subdomains、ips、open_ports、fingerprints、sensitive_paths、apis、screenshots、vuln_hints、leak_info、discovered_assets
- **直接覆盖**：user_input、conversation_history、target、target_type、current_phase、has_cdn、has_waf、real_ip、iteration、max_iterations、new_asset_found、skip_cache

### 5.2 各节点核心职责

1. **plan_node LLM 动态规划**：读取当前状态传入提示词，LLM 输出阶段 + 任务列表；LLM 调用失败自动降级基础扫描任务模板。

2. **passive_node 并发被动执行**：提取 task_list 中所有被动工具，通过注册表获取工具实例，`asyncio.gather` 批量并发执行，收集全部 ToolResult 增量写入状态。

3. **active_node 多资产并行扫描**：识别所有未扫描子域名 / IP，使用 asyncio 为每个资产创建独立并发分支，互不阻塞。

4. **error_handler_node 错误容灾**：读取状态内 errors 列表，区分网络超时类可重试错误、致命错误、普通异常；可重试任务放回任务队列，其余直接跳过。

5. **reflect_node 反思迭代**：对比本轮新资产与 discovered_assets 全局集合，提取新增资产更新状态；赋值 new_asset_found；无新资产则终止迭代循环。

6. **analyze_node 漏洞匹配**：调用 `vuln_match_tool`，基于 Chroma CVE 向量库 RAG 检索，存入 vuln_hints。

7. **report_node 报告生成**：整合全量资产、漏洞、泄露、防护信息，输出 Markdown/JSON/CSV 多格式报告。

### 5.3 CDN 专属条件分支

入口 → plan_node 生成基础任务 → CDN 条件分支判断：

- 若 `has_cdn=True 且 real_ip 为空`：优先强制执行 `cdn_bypass` 任务，挖掘真实 IP 后再执行主动扫描
- 若 `has_cdn=True 且 real_ip 不为空`：直接使用真实 IP 执行端口、指纹、目录扫描，规避 CDN 防护
- 若 `has_cdn=False`：执行常规全量主动扫描流程

### 5.4 完整工作流流转逻辑

入口 → plan_node 生成任务 → CDN 条件分支适配 → 对应阶段并发执行工具 → 失败进入 error_handler 处理 → reflect_node 判断是否有新资产

- new_asset_found=True 且未达最大迭代次数：回到 plan_node 重新规划针对性任务
- new_asset_found=False：进入 analyze 漏洞匹配 → report 生成报告，流程结束

## 6. RAG 知识库层

### 6.1 Chroma 向量库封装

- 初始化强制传入 Embedding
- 使用本地 `sentence-transformers` 离线模型 `all-MiniLM-L6-v2`
- 独立集合：`cve_knowledge`
- 提供同步接口 `scripts/sync_cve_task.py` 拉取 NVD 数据入库

### 6.2 指纹体系分层分工

- **本地精准规则（fingerprint_db.json）**：基于 header、response_body、favicon_hash、title、cookie、html 标签等固定规则，快速识别已知 CMS、中间件、版本，速度快、误报率低。

- **向量知识库（cve_knowledge）**：基于 NVD CVE 数据，通过语义检索召回相关漏洞，再用 CPE vendor/product + 版本范围做精确过滤，补充精准规则库覆盖不到的组件和版本。

### 6.3 CVE 同步流程

```bash
# 增量同步
python scripts/sync_cve_task.py

# 全量同步
python scripts/sync_cve_task.py --full

# 指定日期
python scripts/sync_cve_task.py --since 2026-07-01

# 试运行
python scripts/sync_cve_task.py --dry-run
```

NVD API Key 可选但推荐：
- 有 Key：0.6 秒/请求
- 无 Key：6 秒/请求

申请地址：https://nvd.nist.gov/developers/request-an-api-key

## 7. 全局并发与限流配置

所有并发、限流参数统一收纳至 `config/settings.py`：

```python
MAX_CONCURRENT_PASSIVE_TOOLS = 8      # 被动工具最大并发数
MAX_CONCURRENT_ASSETS = 5              # 多资产并行扫描最大并发数
RATE_LIMIT_PER_SECOND = 10             # 单目标每秒请求频率限制
CACHE_TTL = 3600                       # 工具缓存 TTL（秒）
MAX_ITERATIONS = 30                    # 最大迭代次数
PASSIVE_TOOL_TIMEOUT = 10              # 被动工具超时（秒）
ACTIVE_TOOL_TIMEOUT = 300              # 主动工具超时（秒）
```

## 8. 启动前置自检能力

`utils/startup_check.py` 项目启动前自动执行环境校验：

- 环境变量校验：检查 .env 核心配置、LLM API Key 完整性
- 外部工具校验：检测 nmap、subfinder、ffuf、playwright 等依赖工具是否安装可用
- 目录权限校验：检测缓存、日志、报告、向量库目录读写权限
- 依赖版本基础校验：规避核心包版本不兼容问题

## 9. 入口文件规范

统一采用命令行参数 CLI 启动：

```bash
# 全流程扫描单个目标
python main.py -t example.com -s full

# 仅执行被动信息收集
python main.py -t example.com -s passive

# 仅执行主动扫描
python main.py -t example.com -s active

# 对话模式
python main.py

# 跳过启动自检
python main.py -t example.com --no-check
```

## 10. 依赖管理

本项目使用 `requirements.txt` 管理依赖，不依赖 Poetry。

```text
# LangGraph LangChain 核心
langchain>=0.3.0
langgraph>=0.2.0
langchain-openai>=0.2.0

# 数据模型与配置
pydantic>=2.0.0
python-dotenv>=1.0.0

# HTTP 客户端
httpx>=0.27.0

# 扫描工具依赖
python-whois>=0.9.0
dnspython>=2.6.0

# 报告与模板
jinja2>=3.1.0

# 向量库与嵌入
chromadb>=0.5.0
sentence-transformers>=2.2.0

# 测试
pytest>=8.0.0
pytest-mock>=3.12.0
```

## 11. 可观测性设计

1. 结构化 JSON 日志，`data/logs` 按阶段分目录存储
2. 每条日志携带目标、工具、耗时、错误、资产明细
3. FastAPI 接口可实时返回扫描进度

## 12. 测试体系分层

1. 工具单元测试：Mock 网络请求，验证解析逻辑、缓存、重试逻辑、注册表映射
2. 节点单元测试：单独校验 plan/reflect/error_handler/CDN 分支输出逻辑
3. 全流程集成测试：模拟小型目标完整流转，验证分支、迭代、终止逻辑

## 13. 推荐分阶段实施路径

### 阶段 1：最小可用闭环（基础框架）

1. 完成 ReconState 状态规约、tools 基类 + ToolResult + 工具注册表
2. 实现 plan_node 降级模板、passive_node、report_node、启动自检
3. 接入 whois、subfinder、nmap 三个基础工具，跑通 CLI 单轮扫描

### 阶段 2：智能调度迭代能力

1. 改造 plan_node 为 LLM 动态规划
2. 完善 reflect_node 资产去重、迭代判断逻辑，实现多轮自动扫描

### 阶段 3：并发、容灾与 CDN 分支完善

1. passive_node 改造 asyncio 并发执行，接入全局并发限流配置
2. active_node 接入多资产并行分支
3. 完善 error_handler 错误隔离、重试机制
4. 落地 CDN 专属条件分支，完善真实 IP 扫描逻辑

### 阶段 4：知识库分层 + 工程化完善

1. 封装带 Embedding 的 Chroma 向量库，明确指纹精准/模糊分层匹配逻辑
2. 接入 NVD 自动同步脚本
3. 开发 FastAPI 接口、完善分层日志、补全全套单元/集成测试

## 14. 核心技术选型决策表

| 需求点 | 选型方案 | 选择理由 |
|-------|---------|---------|
| 工作流引擎 | LangGraph | 原生支持状态持久、条件分支、Send 动态子分支、自定义 reducer |
| 并发方案 | asyncio + Semaphore | 轻量无额外中间件，和框架原生兼容，支持自定义并发限流 |
| 向量数据库 | 本地 Chroma | 无需独立服务，本地开发开箱即用，支持持久化存储 |
| 嵌入模型 | sentence-transformers | 离线本地模型，无需 API Key，首次自动下载 |
| 缓存机制 | 本地文件缓存 + TTL | 轻量化，减少重复外网请求，统一过期清理 |
| 日志格式 | 结构化 JSON | 便于后续日志检索、告警分析、问题定位 |
| 依赖管控 | requirements.txt | 使用 pip 标准工具，维护成本低 |
| 对外调用 | FastAPI | 轻量异步接口，支持前端/第三方系统对接 |
| 指纹识别体系 | 本地精准规则 + 向量模糊检索双分层 | 兼顾扫描速度、准确率与泛化能力，互补无盲区 |
| 启动校验 | 前置自检脚本 | 提前拦截环境、配置问题，提升工程稳定性 |
| CVE 数据源 | NVD API | 官方权威数据源，支持增量同步 |

## 15. 法律提示

仅可对自身拥有、已获取书面授权的资产执行主动扫描，非法对公网站点扫描存在法律风险。
