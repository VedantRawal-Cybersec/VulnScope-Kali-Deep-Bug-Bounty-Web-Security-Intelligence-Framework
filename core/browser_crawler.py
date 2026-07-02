#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from core.crawler_v2 import canonicalize, same_scope
from core.parameter_inventory import add_params_from_url
from core.scan_state import ScanState


@dataclass
class BrowserCrawlResult:
    enabled: bool
    status: str
    routes_added: int = 0
    error: str = ""


class BrowserCrawler:
    """Optional Playwright crawler for JS-rendered links and network routes.

    This module is transparent: normal browser automation, no stealth plugins, no hidden routing.
    It is skipped automatically when Playwright is unavailable.
    """

    def __init__(self, *, state: ScanState, include_subdomains: bool = False, dashboard: object | None = None, max_routes: int = 80) -> None:
        self.state = state
        self.include_subdomains = include_subdomains
        self.dashboard = dashboard
        self.max_routes = max(1, int(max_routes))

    def _event(self, message: str) -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", message)
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="Browser route discovery", action=message, probe_string="browser-transparent", evidence=f"browser_routes={self.state.stats.get('browser_routes', 0)}", safety_status="transparent optional browser crawl; no stealth mode")

    def run(self) -> BrowserCrawlResult:
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception:
            self.state.add_event("INFO", "Playwright not installed; browser route discovery skipped")
            return BrowserCrawlResult(enabled=False, status="skipped", error="playwright not installed")
        routes: set[str] = set()
        self._event("Starting optional browser route discovery")
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                page = browser.new_page(user_agent="VulnScope-Autonomous-Safe-Scanner/1.8 Browser")
                page.on("request", lambda req: routes.add(req.url))
                page.goto(self.state.target, wait_until="domcontentloaded", timeout=20000)
                page.wait_for_timeout(1500)
                for selector in ["a[href]", "button", "[role=button]"]:
                    try:
                        locators = page.locator(selector)
                        count = min(locators.count(), 25)
                        for idx in range(count):
                            try:
                                locators.nth(idx).hover(timeout=500)
                            except Exception:
                                pass
                    except Exception:
                        pass
                links = page.locator("a[href]")
                for idx in range(min(links.count(), 200)):
                    try:
                        href = links.nth(idx).get_attribute("href")
                        if href:
                            routes.add(page.url.split("#")[0].rstrip("/") + "/" if href == "/" else href)
                    except Exception:
                        pass
                browser.close()
        except Exception as exc:
            return BrowserCrawlResult(enabled=True, status="failed", error=str(exc)[:500])
        added = 0
        for raw in list(routes)[: self.max_routes * 2]:
            try:
                url = canonicalize(raw)
                if same_scope(url, self.state.host, self.include_subdomains):
                    self.state.add_url(url, depth=1, source="browser")
                    add_params_from_url(self.state, url, "browser")
                    added += 1
                    if added >= self.max_routes:
                        break
            except Exception:
                continue
        self.state.stats["browser_routes"] = int(self.state.stats.get("browser_routes", 0)) + added
        self.state.save()
        self._event(f"Browser route discovery completed: added={added}")
        return BrowserCrawlResult(enabled=True, status="completed", routes_added=added)
