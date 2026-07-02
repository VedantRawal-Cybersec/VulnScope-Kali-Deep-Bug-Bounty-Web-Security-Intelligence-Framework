#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse
from urllib import robotparser

import requests

from cai_scope_guard import cai_output_dir, normalize_target
from core.parameter_extractor import FormRecord, ParameterRecord, dedupe_parameters, extract_from_form, extract_from_network_request, extract_from_url, normalize_url

ASSET_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".css",
    ".woff", ".woff2", ".ttf", ".otf", ".pdf", ".zip", ".mp4", ".webm",
)
SENSITIVE_PATH_HINTS = ("logout", "delete", "remove", "checkout", "payment", "upload", "password")
DEFAULT_UA = "VulnScope-Authorized-SafeCrawler/2.0"


@dataclass
class CrawlConfig:
    target: str
    render_js: bool = True
    max_pages: int = 300
    min_pages_goal: int = 200
    max_depth: int = 3
    page_timeout_ms: int = 15000
    network_idle_timeout_ms: int = 5000
    delay: float = 0.2
    include_subdomains: bool = False
    respect_robots: bool = True
    user_agent: str = DEFAULT_UA


@dataclass
class CrawlResult:
    target: str
    render_js: bool
    urls: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    api_routes: list[str] = field(default_factory=list)
    network_requests: list[dict[str, Any]] = field(default_factory=list)
    parameters: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


class StaticParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[FormRecord] = []
        self.inline_script = ""
        self._in_script = False
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        values = {k.lower(): v or "" for k, v in attrs}
        if tag in {"a", "link"} and values.get("href"):
            self.links.add(urljoin(self.base_url, values["href"]).split("#")[0])
        if tag == "script":
            self._in_script = True
            if values.get("src"):
                self.scripts.add(urljoin(self.base_url, values["src"]).split("#")[0])
        if tag == "form":
            self._form = {
                "method": (values.get("method") or "GET").upper(),
                "action": urljoin(self.base_url, values.get("action") or self.base_url),
                "enctype": values.get("enctype") or "application/x-www-form-urlencoded",
                "fields": {},
            }
        if self._form is not None and tag in {"input", "select", "textarea"}:
            name = values.get("name")
            if name:
                self._form["fields"][name] = values.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "script":
            self._in_script = False
        if tag == "form" and self._form is not None:
            self.forms.append(FormRecord(
                page_url=self.base_url,
                action_url=str(self._form["action"]),
                method=str(self._form["method"]),
                enctype=str(self._form["enctype"]),
                fields=dict(self._form["fields"]),
            ))
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_script and data:
            self.inline_script += "\n" + data[:50000]


def is_asset(url: str) -> bool:
    return (urlparse(url).path or "").lower().endswith(ASSET_EXTENSIONS)


def same_scope(url: str, base_host: str, include_subdomains: bool = False) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    base_host = base_host.lower()
    return parsed.scheme in {"http", "https"} and (host == base_host or (include_subdomains and host.endswith("." + base_host))) and not is_asset(url)


def safe_to_crawl(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return not any(hint in path for hint in SENSITIVE_PATH_HINTS)


def request_line(url: str) -> str:
    parsed = urlparse(url)
    return "GET " + (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")


def extract_route_hints(text: str, base_url: str) -> set[str]:
    routes: set[str] = set()
    patterns = [
        r"fetch\(\s*['\"]([^'\"]+)['\"]",
        r"axios\.(?:get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]",
        r"XMLHttpRequest\([^)]*\)",
        r"['\"](/api/[^'\"\s<>]+)['\"]",
        r"['\"](/[A-Za-z0-9_./-]+\?[^'\"\s<>]+)['\"]",
        r"['\"](https?://[^'\"\s<>]+\?[^'\"\s<>]+)['\"]",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text or "", re.I):
            if match.lastindex:
                routes.add(urljoin(base_url, match.group(1)).split("#")[0])
    return routes


class SafeCrawler:
    def __init__(self, config: CrawlConfig, dashboard: Any | None = None) -> None:
        self.config = config
        self.target = normalize_target(config.target)
        self.base_host = (urlparse(self.target).hostname or "").lower()
        self.dashboard = dashboard
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.user_agent})
        self.urls: set[str] = set()
        self.paths: set[str] = set()
        self.forms: list[FormRecord] = []
        self.scripts: set[str] = set()
        self.api_routes: set[str] = set()
        self.network_requests: list[dict[str, Any]] = []
        self.parameters: list[ParameterRecord] = []
        self.errors: list[dict[str, str]] = []
        self.robots = self._load_robots()

    def _event(self, message: str, *, url: str | None = None, progress: int = 0, evidence: str = "") -> None:
        if self.dashboard is None:
            return
        current = url or self.target
        parsed = urlparse(current)
        query = parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope."
        if hasattr(self.dashboard, "update"):
            self.dashboard.update(
                current_agent="CrawlerAgent",
                current_tool="playwright_crawler" if self.config.render_js else "requests_crawler",
                phase="Playwright Crawl" if self.config.render_js else "Static Crawl",
                phase_progress=progress,
                endpoint=current,
                request_line=request_line(current),
                path=parsed.path or "/",
                parameters=query,
                action=message,
                probe_string="crawl",
                evidence=evidence or f"urls={len(self.urls)} params={len(self.parameters)} forms={len(self.forms)} api={len(self.api_routes)}",
                urls_found=len(self.urls),
                paths_found=len(self.paths),
                params_found=len(self.parameters),
                forms_found=len(self.forms),
                js_found=len(self.scripts),
                api_routes_found=len(self.api_routes),
                safety_status="same-scope browser rendering • robots-aware • GET navigation only",
            )
        if hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", message)

    def _load_robots(self) -> robotparser.RobotFileParser | None:
        if not self.config.respect_robots:
            return None
        parsed = urlparse(self.target)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        rp = robotparser.RobotFileParser()
        try:
            rp.set_url(robots_url)
            rp.read()
            return rp
        except Exception:
            return None

    def allowed_by_robots(self, url: str) -> bool:
        if self.robots is None:
            return True
        try:
            return self.robots.can_fetch(self.config.user_agent, url)
        except Exception:
            return True

    def _add_url(self, url: str, source: str = "crawl") -> bool:
        try:
            url = normalize_url(url)
        except Exception:
            return False
        if not same_scope(url, self.base_host, self.config.include_subdomains):
            return False
        if not safe_to_crawl(url):
            for rec in extract_from_url(url, source=source):
                self.parameters.append(rec)
            return False
        if self.config.respect_robots and not self.allowed_by_robots(url):
            return False
        before = len(self.urls)
        self.urls.add(url)
        self.paths.add(urlparse(url).path or "/")
        for rec in extract_from_url(url, source=source):
            self.parameters.append(rec)
        return len(self.urls) > before

    def _add_form(self, form: FormRecord) -> None:
        self.forms.append(form)
        for rec in extract_from_form(form, source="dom-form"):
            self.parameters.append(rec)

    def _add_network_request(self, request: dict[str, Any]) -> None:
        try:
            url = normalize_url(str(request.get("url") or ""))
        except Exception:
            return
        if not same_scope(url, self.base_host, self.config.include_subdomains):
            return
        request["url"] = url
        self.network_requests.append(request)
        self._add_url(url, source="network")
        for rec in extract_from_network_request(request):
            self.parameters.append(rec)
        if "/api/" in (urlparse(url).path or "").lower() or "graphql" in (urlparse(url).path or "").lower():
            self.api_routes.add(url)

    def import_metadata(self) -> None:
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in ["/robots.txt", "/sitemap.xml"]:
            url = base + path
            try:
                response = self.session.get(url, timeout=8)
            except Exception as exc:
                self.errors.append({"url": url, "error": str(exc)[:300]})
                continue
            if response.status_code != 200:
                continue
            if path.endswith("robots.txt"):
                for match in re.finditer(r"(?im)^\s*(?:Allow|Disallow):\s*(\S+)", response.text):
                    self._add_url(urljoin(base, match.group(1)), source="robots")
            else:
                for match in re.finditer(r"<loc>\s*([^<]+)\s*</loc>", response.text, re.I):
                    self._add_url(match.group(1).strip(), source="sitemap")

    def crawl_static_page(self, url: str) -> list[str]:
        discovered: list[str] = []
        try:
            response = self.session.get(url, timeout=12)
        except Exception as exc:
            self.errors.append({"url": url, "error": str(exc)[:300]})
            return discovered
        if response.status_code >= 400:
            return discovered
        if "html" not in response.headers.get("Content-Type", "").lower() and "<html" not in response.text[:1000].lower():
            return discovered
        parser = StaticParser(str(response.url))
        try:
            parser.feed(response.text)
        except Exception:
            pass
        for script in parser.scripts:
            if same_scope(script, self.base_host, self.config.include_subdomains):
                self.scripts.add(normalize_url(script))
        for form in parser.forms:
            self._add_form(form)
        for link in parser.links:
            if self._add_url(link, source="html-link"):
                discovered.append(normalize_url(link))
        for route in extract_route_hints(parser.inline_script, str(response.url)):
            if self._add_url(route, source="inline-js"):
                discovered.append(normalize_url(route))
        return discovered

    def crawl_with_playwright(self) -> None:
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception as exc:
            self.errors.append({"url": self.target, "error": f"Playwright not available: {exc}"})
            self.config.render_js = False
            self.crawl_static()
            return

        queue: deque[tuple[str, int]] = deque([(self.target, 0)])
        self._add_url(self.target, source="seed")
        processed = 0
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(user_agent=self.config.user_agent, ignore_https_errors=True)
            while queue and processed < self.config.max_pages:
                url, depth = queue.popleft()
                url = normalize_url(url)
                if depth > self.config.max_depth or not same_scope(url, self.base_host, self.config.include_subdomains):
                    continue
                if not self.allowed_by_robots(url):
                    continue
                progress = int(min(99, processed * 100 / max(1, self.config.max_pages)))
                self._event(f"Rendering page {processed + 1}/{self.config.max_pages} depth={depth}", url=url, progress=progress)
                page = context.new_page()
                captured: list[dict[str, Any]] = []

                def on_request(req: Any) -> None:
                    try:
                        captured.append({
                            "url": req.url,
                            "method": req.method,
                            "headers": dict(req.headers or {}),
                            "post_data": req.post_data or "",
                            "resource_type": req.resource_type,
                            "source": "playwright-network",
                        })
                    except Exception:
                        pass

                page.on("request", on_request)
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=self.config.page_timeout_ms)
                    try:
                        page.wait_for_load_state("networkidle", timeout=self.config.network_idle_timeout_ms)
                    except Exception:
                        pass
                    try:
                        page.wait_for_timeout(600)
                    except Exception:
                        pass
                    current_url = normalize_url(page.url)
                    self._add_url(current_url, source="rendered-page")
                    html = page.content()
                    parser = StaticParser(current_url)
                    try:
                        parser.feed(html)
                    except Exception:
                        pass
                    dom_links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href).filter(Boolean)")
                    dom_scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src).filter(Boolean)")
                    dom_forms = page.eval_on_selector_all(
                        "form",
                        "forms => forms.map(f => ({action: f.action || location.href, method: (f.method || 'GET').toUpperCase(), enctype: f.enctype || 'application/x-www-form-urlencoded', fields: Array.from(f.querySelectorAll('input[name],textarea[name],select[name]')).reduce((a,e)=>{a[e.name]=e.value||'';return a;}, {})}))",
                    )
                    for req in captured:
                        self._add_network_request(req)
                    for script in list(dom_scripts or []) + list(parser.scripts):
                        if same_scope(str(script), self.base_host, self.config.include_subdomains):
                            self.scripts.add(normalize_url(str(script)))
                    for form_data in list(dom_forms or []):
                        if isinstance(form_data, dict):
                            form = FormRecord(
                                page_url=current_url,
                                action_url=str(form_data.get("action") or current_url),
                                method=str(form_data.get("method") or "GET"),
                                enctype=str(form_data.get("enctype") or "application/x-www-form-urlencoded"),
                                fields=dict(form_data.get("fields") or {}),
                            )
                            self._add_form(form)
                    new_links: list[str] = []
                    for link in list(dom_links or []) + list(parser.links):
                        if self._add_url(str(link), source="dom-link"):
                            new_links.append(normalize_url(str(link)))
                    for route in extract_route_hints(parser.inline_script + "\n" + html, current_url):
                        if self._add_url(route, source="rendered-js-route"):
                            new_links.append(normalize_url(route))
                            if "/api/" in (urlparse(route).path or "").lower() or "graphql" in (urlparse(route).path or "").lower():
                                self.api_routes.add(normalize_url(route))
                    for link in new_links:
                        if len(self.urls) >= self.config.max_pages * 4:
                            break
                        if link not in [item[0] for item in queue]:
                            queue.append((link, depth + 1))
                    processed += 1
                    time.sleep(self.config.delay)
                except Exception as exc:
                    self.errors.append({"url": url, "error": str(exc)[:500]})
                finally:
                    try:
                        page.close()
                    except Exception:
                        pass
            context.close()
            browser.close()
        self._event("Browser crawl completed", progress=100)

    def crawl_static(self) -> None:
        queue: deque[tuple[str, int]] = deque([(self.target, 0)])
        self._add_url(self.target, source="seed")
        processed = 0
        seen: set[str] = set()
        while queue and processed < self.config.max_pages:
            url, depth = queue.popleft()
            url = normalize_url(url)
            if url in seen or depth > self.config.max_depth:
                continue
            seen.add(url)
            self._event(f"Static crawl {processed + 1}/{self.config.max_pages}", url=url, progress=int(processed * 100 / max(1, self.config.max_pages)))
            discovered = self.crawl_static_page(url)
            for link in discovered:
                if link not in seen:
                    queue.append((link, depth + 1))
            processed += 1
            time.sleep(self.config.delay)

    def analyze_scripts(self, limit: int = 50) -> None:
        for idx, script in enumerate(list(self.scripts)[:limit], 1):
            self._event(f"Extracting JS routes {idx}/{min(limit, len(self.scripts))}", url=script, progress=90)
            try:
                response = self.session.get(script, timeout=10)
            except Exception as exc:
                self.errors.append({"url": script, "error": str(exc)[:300]})
                continue
            if response.status_code != 200:
                continue
            for route in extract_route_hints(response.text, script):
                if self._add_url(route, source="external-js"):
                    if "/api/" in (urlparse(route).path or "").lower() or "graphql" in (urlparse(route).path or "").lower():
                        self.api_routes.add(normalize_url(route))

    def run(self) -> CrawlResult:
        self.import_metadata()
        if self.config.render_js:
            self.crawl_with_playwright()
        else:
            self.crawl_static()
        self.analyze_scripts()
        self.parameters = dedupe_parameters(self.parameters)
        paths = sorted({urlparse(u).path or "/" for u in self.urls})
        result = CrawlResult(
            target=self.target,
            render_js=self.config.render_js,
            urls=sorted(self.urls),
            paths=paths,
            forms=[f.to_dict() for f in self.forms],
            scripts=sorted(self.scripts),
            api_routes=sorted(self.api_routes),
            network_requests=self.network_requests[:5000],
            parameters=[p.to_dict() for p in self.parameters],
            errors=self.errors,
            stats={
                "urls_total": len(self.urls),
                "paths_total": len(paths),
                "forms_total": len(self.forms),
                "scripts_total": len(self.scripts),
                "api_routes_total": len(self.api_routes),
                "network_requests": len(self.network_requests),
                "params_total": len(self.parameters),
                "params_safe_to_test": sum(1 for p in self.parameters if p.safe_to_test),
                "errors": len(self.errors),
            },
        )
        out = cai_output_dir(self.target)
        out.mkdir(parents=True, exist_ok=True)
        (out / "crawler-result.json").write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8")
        return result


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="VulnScope Playwright-enabled safe crawler")
    parser.add_argument("--target", required=True)
    parser.add_argument("--render-js", action="store_true", default=False)
    parser.add_argument("--max-pages", type=int, default=300)
    parser.add_argument("--min-pages-goal", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--no-robots", action="store_true")
    args = parser.parse_args()
    crawler = SafeCrawler(CrawlConfig(target=args.target, render_js=args.render_js, max_pages=args.max_pages, min_pages_goal=args.min_pages_goal, max_depth=args.max_depth, delay=args.delay, include_subdomains=args.include_subdomains, respect_robots=not args.no_robots))
    result = crawler.run()
    print(json.dumps({"status": "completed", "stats": result.stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
