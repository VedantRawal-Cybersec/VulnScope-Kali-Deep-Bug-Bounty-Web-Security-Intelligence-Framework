#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from core.crawler_v2 import canonicalize, same_scope
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
    error: str = ""


class BrowserCrawler:
    """Optional Playwright crawler for JS-rendered links, GET forms, and network routes.

    It is transparent and safe: no stealth plugins, no hidden routing, no form submission.
    """

    def __init__(self, *, state: ScanState, include_subdomains: bool = False, dashboard: object | None = None, max_routes: int = 500) -> None:
        self.state = state
        self.include_subdomains = include_subdomains
        self.dashboard = dashboard
        self.max_routes = max(1, int(max_routes))
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
                phase="Browser route discovery",
                action=message,
                probe_string="browser-transparent",
                evidence=f"browser_routes={self.state.stats.get('browser_routes', 0)} params={len(self.state.params)}",
                urls_found=len(self.state.urls),
                paths_found=len(paths),
                params_found=len(self.state.params),
                safety_status="transparent optional browser crawl; no form submission; no stealth mode",
            )

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
        self._event("Starting optional browser route discovery")
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(user_agent="VulnScope-Autonomous-Safe-Scanner/1.9 Browser", ignore_https_errors=True)
                page = context.new_page()

                def on_request(req: object) -> None:
                    try:
                        url = canonicalize(getattr(req, "url"))
                        network_urls.add(url)
                    except Exception:
                        pass

                page.on("request", on_request)
                page.goto(self.state.target, wait_until="domcontentloaded", timeout=20000)
                self._remember_host(page.url)
                try:
                    page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass
                page.wait_for_timeout(1000)

                for item in list(network_urls):
                    if self._in_scope(item):
                        routes.add(item)

                try:
                    links = page.eval_on_selector_all("a[href],link[href]", "els => els.map(e => e.href).filter(Boolean)")
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

                context.close()
                browser.close()
        except Exception as exc:
            return BrowserCrawlResult(enabled=True, status="failed", error=str(exc)[:500])

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
        self.state.save()
        self._event(f"Browser route discovery completed: urls={added} params_added={params_added} forms={forms_added}")
        return BrowserCrawlResult(enabled=True, status="completed", routes_added=added, params_added=params_added, forms_added=forms_added, network_requests=len(network_urls))
