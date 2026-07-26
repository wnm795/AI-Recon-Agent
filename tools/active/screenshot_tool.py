# 页面截图工具
# 基于 Playwright 无头浏览器截图，支持页面加载超时控制

from pathlib import Path
from typing import Any

from tools.base import BaseTool
from config.settings import REPORTS_DIR


class ScreenshotTool(BaseTool):
    """
    页面截图工具

    使用 Playwright 进行无头浏览器截图
    Playwright 未安装时降级到错误提示
    """

    tool_name = "screenshot"
    description = "Web 页面无头截图"
    timeout = 30
    max_retries = 1
    cache_ttl = 0
    is_passive = False

    async def _execute(self, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行页面截图"""
        url = f"http://{target}" if not target.startswith("http") else target

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {
                "target": target,
                "screenshot_path": "",
                "error": "Playwright 未安装，请运行: pip install playwright && playwright install",
            }

        output_dir = REPORTS_DIR / "screenshots"
        output_dir.mkdir(parents=True, exist_ok=True)

        safe_name = target.replace(".", "_").replace(":", "_").replace("/", "_")
        output_path = output_dir / f"{safe_name}.png"

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")
                await page.screenshot(path=str(output_path), full_page=True)
                await browser.close()

            return {
                "target": target,
                "screenshot_path": str(output_path),
                "url": url,
            }
        except Exception as e:
            return {
                "target": target,
                "screenshot_path": "",
                "error": str(e),
            }
