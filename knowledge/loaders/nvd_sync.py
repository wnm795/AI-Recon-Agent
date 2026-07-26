# NVD API 增量同步模块
# 定期同步近 7 天新增 CVE 漏洞数据，保持知识库时效性

import asyncio
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from config.settings import DATA_DIR


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
# NVD 官方限速：无 Key 建议 6 秒，有 Key 建议 0.6 秒
NVD_RATE_LIMIT_DELAY = 0.6 if NVD_API_KEY else 6.0
MAX_RESULTS_PER_PAGE = 2000

# 同步游标文件，记录最后一次成功同步的时间
SYNC_CURSOR_FILE = DATA_DIR / "nvd_sync_cursor.json"


def _ensure_data_dir() -> None:
    """确保数据目录存在"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_sync_cursor() -> dict[str, Any]:
    """加载同步游标"""
    _ensure_data_dir()
    if not SYNC_CURSOR_FILE.exists():
        return {"last_sync_time": "", "total_synced": 0}
    try:
        import json
        with open(SYNC_CURSOR_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"last_sync_time": "", "total_synced": 0}


def save_sync_cursor(cursor: dict[str, Any]) -> None:
    """保存同步游标"""
    _ensure_data_dir()
    import json
    with open(SYNC_CURSOR_FILE, "w", encoding="utf-8") as f:
        json.dump(cursor, f, ensure_ascii=False, indent=2)


def _format_nvd_time(dt: datetime) -> str:
    """格式化为 NVD API 要求的 ISO 8601 格式（带 UTC 时区）"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000") + "Z"


def _parse_nvd_time(time_str: str) -> datetime:
    """解析 NVD API 返回的时间字符串"""
    time_str = time_str.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(time_str)
    except ValueError:
        return datetime.now(timezone.utc)


async def _fetch_page(
    client: httpx.AsyncClient,
    params: dict[str, Any],
    retries: int = 3,
) -> dict[str, Any]:
    """
    分页请求 NVD API，带限速和重试

    Args:
        client: httpx 异步客户端
        params: 请求参数
        retries: 最大重试次数

    Returns:
        NVD API 返回的 JSON 数据
    """
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    last_error = None
    for attempt in range(1, retries + 1):
        try:
            # 限速
            await asyncio.sleep(NVD_RATE_LIMIT_DELAY)

            response = await client.get(
                NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=60.0,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            last_error = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
            if e.response.status_code in (403, 429):
                # 限速或被封，多等待一会再重试
                wait = NVD_RATE_LIMIT_DELAY * (2 ** attempt)
                print(f"[nvd_sync] 请求被限制，{wait:.1f}s 后重试 ({attempt}/{retries})")
                await asyncio.sleep(wait)
                continue
            raise
        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
            wait = NVD_RATE_LIMIT_DELAY * attempt
            print(f"[nvd_sync] 请求异常，{wait:.1f}s 后重试 ({attempt}/{retries}): {last_error}")
            await asyncio.sleep(wait)

    raise RuntimeError(f"NVD API 请求失败（已重试 {retries} 次）: {last_error}")


async def sync_cves(
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> list[dict[str, Any]]:
    """
    同步指定时间窗口内的 CVE 数据

    Args:
        start_date: 开始时间（lastModStartDate），None 表示从游标读取
        end_date: 结束时间（lastModEndDate），None 表示当前时间

    Returns:
        原始 CVE 条目列表（NVD API 的 vulnerabilities[].cve）
    """
    cursor = load_sync_cursor()

    if end_date is None:
        end_date = datetime.now(timezone.utc)

    if start_date is None:
        last_sync = cursor.get("last_sync_time", "")
        if last_sync:
            start_date = _parse_nvd_time(last_sync)
        else:
            # 首次同步：默认拉取近 30 天
            start_date = end_date - timedelta(days=30)
            print("[nvd_sync] 首次同步，默认拉取近 30 天数据")

    # NVD 要求时间窗口不超过 120 天
    if (end_date - start_date).days > 120:
        print("[nvd_sync] 时间窗口超过 120 天，自动截取为 120 天")
        start_date = end_date - timedelta(days=120)

    all_vulnerabilities: list[dict[str, Any]] = []
    start_index = 0
    total_results = None

    params = {
        "lastModStartDate": _format_nvd_time(start_date),
        "lastModEndDate": _format_nvd_time(end_date),
        "resultsPerPage": MAX_RESULTS_PER_PAGE,
        "startIndex": start_index,
    }

    async with httpx.AsyncClient() as client:
        while True:
            params["startIndex"] = start_index
            data = await _fetch_page(client, params)

            if total_results is None:
                total_results = data.get("totalResults", 0)
                print(f"[nvd_sync] 本次共需同步 {total_results} 条 CVE")

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                cve = item.get("cve", {})
                if cve:
                    all_vulnerabilities.append(cve)

            start_index += len(vulnerabilities)
            print(f"[nvd_sync] 已获取 {start_index}/{total_results} 条")

            if start_index >= total_results:
                break

    return all_vulnerabilities


async def full_sync() -> list[dict[str, Any]]:
    """全量同步：从 1999 年开始按年份分批拉取（用于首次初始化）"""
    end_date = datetime.now(timezone.utc)
    start_year = 1999
    all_vulnerabilities: list[dict[str, Any]] = []

    for year in range(start_year, end_date.year + 1):
        start_date = datetime(year, 1, 1, tzinfo=timezone.utc)
        year_end = datetime(year, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        if year_end > end_date:
            year_end = end_date

        print(f"[nvd_sync] 同步 {year} 年数据...")
        try:
            year_cves = await sync_cves(start_date, year_end)
            all_vulnerabilities.extend(year_cves)
        except Exception as e:
            print(f"[nvd_sync] {year} 年同步失败: {e}")
            continue

    return all_vulnerabilities


def update_cursor_after_sync(end_date: datetime | None = None) -> None:
    """同步完成后更新游标"""
    if end_date is None:
        end_date = datetime.now(timezone.utc)
    cursor = load_sync_cursor()
    cursor["last_sync_time"] = _format_nvd_time(end_date)
    save_sync_cursor(cursor)
