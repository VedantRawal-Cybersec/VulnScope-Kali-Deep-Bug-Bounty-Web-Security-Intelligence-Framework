from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urljoin, urlparse

from auth.playwright_login import playwright_available


def crawl_authenticated(base_url: str, state_path: Path, label: str, max_pages: int = 10, headless: bool = True) -> dict:
    if not playwright_available():
        raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install chromium")

    from playwright.sync_api import sync_playwright

    parsed_base = urlparse(base_url)
    host = parsed_base.netloc
    visited: set[str] = set()
    queue = [base_url]
    pages = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(storage_state=str(state_path))
        page = context.new_page()
        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            if urlparse(url).netloc and urlparse(url).netloc != host:
                continue
            visited.add(url)
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=45000)
                title = page.title()
                text = page.locator("body").inner_text(timeout=5000)[:5000] if page.locator("body").count() else ""
                links = page.eval_on_selector_all("a[href]", "els => els.map(a => a.href)")
                same_domain_links = []
                for link in links:
                    absolute = urljoin(url, link)
                    if urlparse(absolute).netloc == host and absolute not in visited and len(queue) < max_pages * 3:
                        same_domain_links.append(absolute)
                        queue.append(absolute)
                pages.append({"url": page.url, "title": title, "text_sample": text, "links": same_domain_links[:50]})
            except Exception as exc:
                pages.append({"url": url, "error": str(exc)})
        browser.close()

    result = {"label": label, "base_url": base_url, "page_count": len(pages), "pages": pages}
    out = Path("reports/output/auth")
    out.mkdir(parents=True, exist_ok=True)
    (out / f"auth-crawl-{label}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result
