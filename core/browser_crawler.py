#!/usr/bin/env python3
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from urllib.parse import urlparse

from core.crawler_v2 import canonicalize, extract_inline_routes, same_scope
from core.parameter_inventory import add_get_form_params, add_params_from_url
from core.scan_state import ScanState


@dataclass
class BrowserCrawlResult:
    enabled: bool
    status: str
    routes_added: int = 0
    params_added: int = 0
    forms_added: int = 0
    network_requests: int = 0
    pages_rendered: int = 0
    error: str = ""


class BrowserCrawler:
    """Transparent Playwright route discovery.

    It renders a bounded set of in-scope pages, scrolls to trigger lazy content,
    captures network URLs, extracts DOM links/scripts/forms, and never submits forms.
    """

    def __init__(self, *, state: ScanState, include_subdomains: bool = False, dashboard: object | None = None, max_routes: int = 500, max_pages: int = 20) -> None:
        self.state = state
        self.include_subdomains = include_subdomains
        self.dashboard = dashboard
        self.max_routes = max(1, int(max_routes))
        self.max_pages = max(1, int(max_pages))
        self.allowed_hosts: set[str] = {state.host}

    def _in_scope(self, url: str) -> bool:
        return same_scope(url, self.state.host, self.include_subdomains, self.allowed_hosts)

    def _remember_host(self, url: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        base = self.state.host.lower()
        if host and (host == base or host.endswith("." + base) or base.endswith("." + host)):
            self.allowed_hosts.add(host)
            self.state.stats["browser_allowed_hosts"] = sorted(self.allowed_hosts)

    def _event(self, message: str) -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", message)
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            paths = {urlparse(item.url).path or "/" for item in self.state.urls.values()}
            self.dashboard.update(
                current_agent="CrawlerAgent",
                current_tool="browser_crawler",
                phase="Browser deep discovery",
                action=message,
                probe_string="browser-transparent",
                evidence=f"browser_routes={self.state.stats.get('browser_routes', 0)} params={len(self.state.params)} pages={self.state.stats.get('browser_pages_rendered', 0)}",
                urls_found=len(self.state.urls),
                paths_found=len(paths),
                params_found=len(self.state.params),
                safety_status="transparent browser crawl; no form submission; no stealth mode",
            )

    def _seed_queue(self) -> deque[str]:
        seeds = [self.state.target]
        for item in sorted(self.state.urls.values(), key=lambda rec: (rec.depth, rec.discovered_at))[: self.max_pages * 3]:
            if item.url not in seeds:
                seeds.append(item.url)
        return deque(seeds)

    def run(self) -> BrowserCrawlResult:
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception:
            self.state.add_event("INFO", "Playwright not installed; browser route discovery skipped")
            return BrowserCrawlResult(enabled=False, status="skipped", error="playwright not installed")

        routes: set[str] = set()
        network_urls: set[str] = set()
        forms_added = 0
        params_added = 0
        pages_rendered = 0
        queue = self._seed_queue()
        visited: set[str] = set()
        self._event("Starting browser deep discovery")
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(user_agent="VulnScope-Autonomous-Safe-Scanner/1.10 Browser", ignore_https_errors=True)
                while queue and pages_rendered < self.max_pages and len(routes) < self.max_routes * 2:
                    target_url = queue.popleft()
                    try:
                        target_url = canonicalize(target_url)
                    except Exception:
                        continue
                    if target_url in visited or not self._in_scope(target_url):
                        continue
                    visited.add(target_url)
                    page = context.new_page()

                    def on_request(req: object) -> None:
                        try:
                            url = canonicalize(getattr(req, "url"))
                            network_urls.add(url)
                        except Exception:
                            pass

                    page.on("request", on_request)
                    try:
                        self._event(f"Rendering browser page {pages_rendered + 1}/{self.max_pages}: {target_url}")
                        page.goto(target_url, wait_until="domcontentloaded", timeout=20000)
                        self._remember_host(page.url)
                        try:
                            page.wait_for_load_state("networkidle", timeout=7000)
                        except Exception:
                            pass
                        for _ in range(3):
                            try:
                                page.mouse.wheel(0, 2500)
                                page.wait_for_timeout(350)
                            except Exception:
                                break
                        html = page.content()
                        for item in list(network_urls):
                            if self._in_scope(item):
                                routes.add(item)
                        try:
                            links = page.eval_on_selector_all("a[href],link[href],area[href],iframe[src]", "els => els.map(e => e.href || e.src).filter(Boolean)")
                            for href in links or []:
                                routes.add(str(href))
                        except Exception:
                            pass
                        try:
                            scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src).filter(Boolean)")
                            for src in scripts or []:
                                routes.add(str(src))
                        except Exception:
                            pass
                        try:
                            forms = page.eval_on_selector_all(
                                "form",
                                "forms => forms.map(f => ({action: f.action || location.href, method: (f.method || 'GET').toUpperCase(), fields: Array.from(f.querySelectorAll('input[name],textarea[name],select[name]')).reduce((a,e)=>{a[e.name]=e.value||'';return a;}, {})}))",
                            )
                            for form in forms or []:
                                if not isinstance(form, dict):
                                    continue
                                method = str(form.get("method") or "GET").upper()
                                action = str(form.get("action") or page.url)
                                fields = dict(form.get("fields") or {})
                                if method == "GET" and fields and self._in_scope(action):
                                    params_added += add_get_form_params(self.state, action, fields, "browser-get-form")
                                    forms_added += 1
                        except Exception:
                            pass
                        for route in extract_inline_routes(html, page.url):
                            routes.add(route)
                        pages_rendered += 1
                        for route in list(routes):
                            try:
                                normalized = canonicalize(route)
                            except Exception:
                                continue
                            if self._in_scope(normalized) and normalized not in visited and len(queue) < self.max_pages * 3:
                                queue.append(normalized)
                    except Exception as exc:
                        self.state.add_event("WARNING", "browser page failed", url=target_url, error=str(exc)[:300])
                    finally:
                        try:
                            page.close()
                        except Exception:
                            pass
                context.close()
                browser.close()
        except Exception as exc:
            return BrowserCrawlResult(enabled=True, status="failed", error=str(exc)[:500], pages_rendered=pages_rendered)

        added = 0
        for raw in list(routes)[: self.max_routes * 2]:
            try:
                url = canonicalize(raw)
                self._remember_host(url)
                if self._in_scope(url):
                    self.state.add_url(url, depth=1, source="browser")
                    params_added += add_params_from_url(self.state, url, "browser")
                    added += 1
                    if added >= self.max_routes:
                        break
            except Exception:
                continue
        self.state.stats["browser_routes"] = int(self.state.stats.get("browser_routes", 0)) + added
        self.state.stats["browser_forms"] = int(self.state.stats.get("browser_forms", 0)) + forms_added
        self.state.stats["browser_pages_rendered"] = int(self.state.stats.get("browser_pages_rendered", 0)) + pages_rendered
        self.state.stats["browser_network_requests"] = int(self.state.stats.get("browser_network_requests", 0)) + len(network_urls)
        self.state.save()
        self._event(f"Browser deep discovery completed: pages={pages_rendered} urls={added} params_added={params_added} forms={forms_added}")
        return BrowserCrawlResult(enabled=True, status="completed", routes_added=added, params_added=params_added, forms_added=forms_added, network_requests=len(network_urls), pages_rendered=pages_rendered)
