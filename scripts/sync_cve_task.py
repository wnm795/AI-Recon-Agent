# 定时同步 CVE 数据脚本
# 调用 NVD API 增量同步最新漏洞数据，保持知识库时效性

import argparse
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

# 确保项目根目录在 Python 路径中
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from knowledge.loaders.nvd_sync import (
    full_sync,
    sync_cves,
    update_cursor_after_sync,
)
from knowledge.loaders.cve_loader import (
    get_cve_count,
    load_cves_to_vector_store,
    parse_cve,
)


def parse_date(date_str: str) -> datetime:
    """解析命令行日期参数"""
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"无法解析日期: {date_str}")


async def run_sync(full: bool = False, since: datetime | None = None, dry_run: bool = False) -> None:
    """
    执行 CVE 同步任务

    Args:
        full: 是否全量同步
        since: 指定开始时间
        dry_run: 试运行，不写入向量库
    """
    print("=" * 60)
    print("【CVE 知识库同步任务】")
    print("=" * 60)

    before_count = get_cve_count()
    print(f"[sync] 同步前向量库 CVE 数量: {before_count}")

    if full:
        print("[sync] 开始全量同步（按年份分批拉取，耗时较长）...")
        raw_cves = await full_sync()
    else:
        print("[sync] 开始增量同步...")
        raw_cves = await sync_cves(start_date=since)

    print(f"[sync] 从 NVD API 获取 {len(raw_cves)} 条原始 CVE 数据")

    if dry_run:
        print("[sync] 试运行模式，跳过向量库写入")
        print(f"[sync] 将解析前 3 条示例数据：")
        for raw in raw_cves[:3]:
            record = parse_cve(raw)
            if record:
                print(f"  - {record['cve_id']} | {record['severity']} | {record['search_text'][:80]}...")
        return

    # 解析 CVE 数据
    records = [parse_cve(raw) for raw in raw_cves]
    records = [r for r in records if r]
    print(f"[sync] 成功解析 {len(records)} 条 CVE 记录")

    if not records:
        print("[sync] 无新数据需要同步")
        update_cursor_after_sync()
        return

    # 写入向量库
    loaded = load_cves_to_vector_store(records)
    after_count = get_cve_count()

    # 更新同步游标
    update_cursor_after_sync()

    print(f"[sync] 成功写入 {loaded} 条 CVE 记录")
    print(f"[sync] 同步后向量库 CVE 数量: {after_count} (新增 {after_count - before_count})")
    print("[sync] CVE 知识库同步完成")


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(
        description="同步 NVD CVE 数据到本地 Chroma 向量库",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python scripts/sync_cve_task.py              # 增量同步
  python scripts/sync_cve_task.py --full       # 全量同步（首次初始化）
  python scripts/sync_cve_task.py --since 2026-07-01  # 从指定日期同步
  python scripts/sync_cve_task.py --dry-run    # 试运行，不写入数据库
        """,
    )
    parser.add_argument("--full", action="store_true", help="全量同步（从 1999 年开始，耗时较长）")
    parser.add_argument("--since", type=str, help="指定增量同步开始日期，格式 YYYY-MM-DD")
    parser.add_argument("--dry-run", action="store_true", help="试运行，不写入向量库")

    args = parser.parse_args()

    since = None
    if args.since:
        since = parse_date(args.since)

    asyncio.run(run_sync(full=args.full, since=since, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
