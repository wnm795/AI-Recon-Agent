# AI 渗透测试信息收集 Agent

## 项目简介

智能规划、并发执行、自我反思的自动化信息收集 Agent，基于 LangGraph 状态驱动工作流。

支持 CLI 对话式交互与直接扫描两种模式，内置 NVD CVE 向量知识库，可对目标进行被动信息收集、主动扫描、漏洞匹配与报告生成。

## 快速开始

```bash
# 1. 安装依赖（使用 pip）
pip install -r requirements.txt

# 2. 配置环境变量（复制 .env.example 到 .env 并填写）
cp .env.example .env

# 3. 初始化 CVE 知识库（首次同步近 30 天数据）
python scripts/sync_cve_task.py

# 4. 启动对话模式
python main.py

# 5. 或直接扫描目标
python main.py -t example.com -s full
```

## 环境变量

在 `.env` 中配置以下关键变量：

| 变量 | 说明 | 是否必填 |
|------|------|---------|
| `PLANNER_API_KEY` | LLM 规划节点 API Key | 是 |
| `VERIFY_API_BASE` | LLM API Base URL | 是 |
| `DEEPSEEK_API_KEY` | DeepSeek API Key（备用） | 否 |
| `NVD_API_KEY` | NVD API Key，加速 CVE 同步 | 否 |
| `OPENAI_API_KEY` | OpenAI API Key | 否 |

## CLI 使用方式

### 对话模式

```bash
python main.py
```

支持的快捷命令：

| 命令 | 说明 |
|------|------|
| `/help` | 显示帮助 |
| `/tools` | 列出可用工具 |
| `/check` | 一键检查环境 |
| `/clear` | 清空对话历史和缓存 |
| `/fresh` | 清空缓存并强制重新扫描 |
| `/exit` | 退出程序 |

### 直接扫描模式

```bash
# 完整扫描
python main.py -t example.com

# 仅被动扫描
python main.py -t example.com -s passive

# 仅主动扫描
python main.py -t example.com -s active

# 跳过启动自检
python main.py -t example.com --no-check
```

参数说明：

| 参数 | 说明 |
|------|------|
| `-t, --target` | 直接扫描目标（跳过对话） |
| `-s, --scope` | 扫描范围：`full` / `passive` / `active` |
| `--no-check` | 跳过启动自检 |

## CVE 知识库同步

```bash
# 增量同步（日常使用）
python scripts/sync_cve_task.py

# 全量同步（首次初始化，耗时较长）
python scripts/sync_cve_task.py --full

# 从指定日期同步
python scripts/sync_cve_task.py --since 2026-07-01

# 试运行，不写入数据库
python scripts/sync_cve_task.py --dry-run
```

> 建议配置 `NVD_API_KEY` 以提升同步速度（0.6 秒/请求，无 Key 为 6 秒/请求）。

## 项目结构

```
agent信息收集/
├── main.py                      # CLI 入口
├── requirements.txt             # pip 依赖
├── .env.example                 # 环境变量模板
├── config/                      # 全局配置与提示词
│   ├── settings.py
│   └── prompts.py
├── tools/                       # 工具层
│   ├── base.py                  # 工具基类
│   ├── registry.py              # 工具注册表
│   ├── result_model.py          # 统一返回模型
│   ├── passive/                 # 被动工具
│   ├── active/                  # 主动工具
│   └── analysis/                # 分析类工具
├── workflow/                    # LangGraph 工作流
│   ├── state.py                 # 全局状态
│   ├── graph.py                 # 工作流图
│   └── nodes/                   # 工作流节点
├── knowledge/                   # RAG 知识库
│   ├── vector_store.py          # Chroma 封装
│   └── loaders/                 # 数据加载与同步
│       ├── nvd_sync.py
│       ├── cve_loader.py
│       └── ...
├── scripts/                     # 辅助脚本
│   └── sync_cve_task.py         # CVE 同步入口
├── api/                         # FastAPI 接口
│   └── main.py
├── tests/                       # 测试
├── data/                        # 持久化数据
│   ├── chroma_db/               # 向量库
│   ├── cache/                   # 工具缓存
│   ├── logs/                    # 日志
│   └── reports/                 # 扫描报告
└── utils/                       # 工具函数
```

## 实例流程

```
用户输入: "帮我快速扫描 www.baidu.com，进行信息收集"
         ↓
┌─────────────────────────────────────────────────────────┐
│ main.py                                                  │
│ 封装 input_state → app.ainvoke(input_state)              │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│ plan_node (意图分析)                                      │
│ LLM: deepseek-v4-pro                                     │
│ → intent=scan, target=www.baidu.com, scope=full          │
│ → task_list=[whois, subdomain, portscan, ...]            │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│ passive_node (被动收集)                                    │
│ 执行: whois, dns_enum, subdomain, cert_log, wayback...   │
│ 更新: subdomains[], dns_records[], whois_info, ...       │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│ active_node (主动扫描)                                     │
│ 执行: cdn_detect, portscan, http_fingerprint, dir_scan...│
│ 更新: open_ports[], fingerprints[], has_cdn=true         │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│ reflect_node (自我反思)                                    │
│ 检查: new_asset_found? iteration < max_iterations?       │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│ analyze_node (漏洞分析)                                    │
│ 执行: vuln_match工具                                       │
│ 基于 Chroma CVE 向量库 RAG 检索                           │
│ 更新: vuln_hints[]                                        │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│ report_node (报告生成)                                     │
│ Jinja2 渲染 Markdown 报告                                 │
│ 输出: data/reports/report_*.md                           │
└─────────────────────────────────────────────────────────┘
```

## 依赖管理

本项目使用 `requirements.txt` 管理依赖，不依赖 Poetry。

```bash
pip install -r requirements.txt
```

## 法律声明

仅可对自身拥有或已获取书面授权的资产执行扫描。非法对公网站点扫描存在法律风险。
