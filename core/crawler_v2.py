#!/usr/bin/env python3
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from core.evidence_store import body_hash, stable_template_key
from core.http_client_v2 import SafeHttpClientV2
from core.parameter_inventory import add_get_form_params, add_params_from_url
from core.scan_state import ScanState

ASSET_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".zip", ".mp4", ".webm")
SENSITIVE_HINTS = ("login", "logout", "signin", "signup", "register", "reset", "password", "checkout", "payment", "cart", "upload", "delete")


@dataclass
class CrawlResult:
    urls_seen: int
    urls_done: int
    parameters: int
    forms: int
    scripts: int
    skipped: int


class HtmlRouteParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[dict[str, object]] = []
        self.inline_script = ""
        self._in_script = False
        self._form: dict[str, object] | None = None

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
            self._form = {"method": (values.get("method") or "GET").upper(), "action": urljoin(self.base_url, values.get("action") or self.base_url), "params": {}}
        if self._form is not None and tag in {"input", "select", "textarea"}:
            name = values.get("name")
            if name:
                params = self._form.setdefault("params", {})
                if isinstance(params, dict):
                    params[name] = values.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "script":
            self._in_script = False
        if tag == "form" and self._form is not None:
            self.forms.append(dict(self._form))
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_script and data:
            self.inline_script += "\n" + data[:20000]


def canonicalize(url: str) -> str:
    parsed = urlparse(url)
    query = urlencode(parse_qs(parsed.query, keep_blank_values=True), doseq=True)
    return urlunparse((parsed.scheme or "https", parsed.netloc.lower(), parsed.path or "/", "", query, ""))


def is_asset(url: str) -> bool:
    return (urlparse(url).path or "").lower().endswith(ASSET_EXTENSIONS)


def is_sensitive_path(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return any(h in path for h in SENSITIVE_HINTS)


def same_scope(url: str, host: str, include_subdomains: bool = False) -> bool:
    parsed = urlparse(url)
    candidate = (parsed.hostname or "").lower()
    host = host.lower()
    return parsed.scheme in {"http", "https"} and (candidate == host or (include_subdomains and candidate.endswith("." + host))) and not is_asset(url)


def extract_inline_routes(script: str, base_url: str) -> set[str]:
    routes: set[str] = set()
    patterns = [r"['\"](/api/[^'\"\s<>]+)['\"]", r"['\"](/[A-Za-z0-9_./-]+\?[^'\"\s<>]+)['\"]", r"fetch\(['\"]([^'\"]+)['\"]"]
    for pattern in patterns:
        for match in re.finditer(pattern, script or ""):
            routes.add(urljoin(base_url, match.group(1)).split("#")[0])
    return routes


class CrawlerV2:
    def __init__(self, *, state: ScanState, client: SafeHttpClientV2, max_pages: int = 120, max_depth: int = 3, include_subdomains: bool = False, max_same_template: int = 6, dashboard: object | None = None) -> None:
        self.state = state
        self.client = client
        self.max_pages = max(1, int(max_pages))
        self.max_depth = max(0, int(max_depth))
        self.include_subdomains = include_subdomains
        self.max_same_template = max(1, int(max_same_template))
        self.dashboard = dashboard
        self.template_counts: dict[str, int] = {}
        self.script_urls: set[str] = set()
        self.form_count = 0

    def _update(self, message: str, url: str, progress: int) -> None:
        parsed = urlparse(url)
        path = parsed.path or "/"
        query = parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope."
        paths = {urlparse(item.url).path or "/" for item in self.state.urls.values()}
        api_routes = [item.url for item in self.state.urls.values() if "/api/" in (urlparse(item.url).path or "").lower() or "graphql" in (urlparse(item.url).path or "").lower()]
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(
                current_agent="CrawlerAgent",
                current_tool="safe_crawler",
                phase="Crawler v2",
                phase_progress=progress,
                requests=self.client.state.stats.get("requests", 0),
                findings=len(self.state.findings),
                action=message,
                endpoint=url,
                request_line="GET " + path + (("?" + parsed.query) if parsed.query else ""),
                path=path,
                parameters=query,
                domain=parsed.hostname or "—",
                probe_string="crawl",
                evidence=f"urls={len(self.state.urls)} paths={len(paths)} params={len(self.state.params)} forms={self.form_count} scripts={len(self.script_urls)}",
                urls_found=len(self.state.urls),
                paths_found=len(paths),
                params_found=len(self.state.params),
                forms_found=self.form_count,
                js_found=len(self.script_urls),
                api_routes_found=len(api_routes),
                safety_status="same-scope crawl with request budget and adaptive backoff",
            )
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", message)

    def crawl(self) -> CrawlResult:
        queue: deque[tuple[str, int]] = deque([(self.state.target, 0)])
        done = 0
        skipped = 0
        while queue and done < self.max_pages and self.client.budget_remaining() > 0:
            url, depth = queue.popleft()
            url = canonicalize(url)
            if url not in self.state.urls:
                self.state.add_url(url, depth=depth, source="crawler")
            record = self.state.urls[url]
            if record.status in {"done", "skipped", "failed"}:
                continue
            if depth > self.max_depth or not same_scope(url, self.state.host, self.include_subdomains):
                record.status = "skipped"
                skipped += 1
                continue
            if is_sensitive_path(url) and depth > 0:
                record.status = "skipped"
                add_params_from_url(self.state, url, "sensitive-route")
                skipped += 1
                continue
            progress = int(min(99, done * 100 / max(1, self.max_pages)))
            self._update(f"Crawling {done + 1}/{self.max_pages} depth={depth}", url, progress)
            result = self.client.get(url, purpose="crawl")
            record.last_seen_at = result.elapsed_ms
            record.status_code = result.status_code
            if result.error:
                record.status = "failed"
                record.error = result.error
                done += 1
                continue
            record.content_type = result.headers.get("Content-Type", "")
            record.body_hash = body_hash(result.text)
            template = stable_template_key(result.url, result.status_code, result.text)
            record.template_key = template
            self.template_counts[template] = self.template_counts.get(template, 0) + 1
            if self.template_counts[template] > self.max_same_template:
                record.status = "skipped"
                skipped += 1
                done += 1
                continue
            add_params_from_url(self.state, result.url, "crawl-url")
            if "html" in record.content_type.lower() or "<html" in result.text[:1000].lower():
                parser = HtmlRouteParser(result.url)
                try:
                    parser.feed(result.text)
                except Exception:
                    pass
                self.script_urls.update({s for s in parser.scripts if same_scope(s, self.state.host, self.include_subdomains)})
                for form in parser.forms:
                    self.form_count += 1
                    method = str(form.get("method") or "GET").upper()
                    action = str(form.get("action") or result.url)
                    params = form.get("params") if isinstance(form.get("params"), dict) else {}
                    if method == "GET" and params and same_scope(action, self.state.host, self.include_subdomains) and not is_sensitive_path(action):
                        add_get_form_params(self.state, action, dict(params), "get-form")
                for link in parser.links:
                    link = canonicalize(link)
                    if same_scope(link, self.state.host, self.include_subdomains):
                        add_params_from_url(self.state, link, "link-url")
                        if link not in self.state.urls and len(queue) + len(self.state.urls) < self.max_pages * 3:
                            self.state.add_url(link, depth=depth + 1, source="link")
                            queue.append((link, depth + 1))
                for route in extract_inline_routes(parser.inline_script, result.url):
                    route = canonicalize(route)
                    if same_scope(route, self.state.host, self.include_subdomains):
                        add_params_from_url(self.state, route, "inline-js")
                        if route not in self.state.urls and len(queue) + len(self.state.urls) < self.max_pages * 3:
                            self.state.add_url(route, depth=depth + 1, source="inline-js")
                            queue.append((route, depth + 1))
            self._update(f"Completed page {done + 1}: discovered urls={len(self.state.urls)} params={len(self.state.params)}", result.url, progress)
            record.status = "done"
            done += 1
            if done % 5 == 0:
                self.state.save()
        self.state.save()
        return CrawlResult(urls_seen=len(self.state.urls), urls_done=done, parameters=len(self.state.params), forms=self.form_count, scripts=len(self.script_urls), skipped=skipped)

    def analyze_scripts(self, limit: int = 30) -> int:
        count = 0
        for script_url in list(self.script_urls)[:limit]:
            if self.client.budget_remaining() <= 0:
                break
            self._update("Reviewing JavaScript route hints", script_url, min(99, count * 100 // max(1, limit)))
            response = self.client.get(script_url, purpose="javascript-route-review")
            if not response.ok or response.status_code != 200:
                continue
            for route in extract_inline_routes(response.text, response.url):
                route = canonicalize(route)
                if same_scope(route, self.state.host, self.include_subdomains):
                    self.state.add_url(route, depth=1, source="external-js")
                    add_params_from_url(self.state, route, "external-js")
                    count += 1
        self.state.stats["javascript_routes"] = count
        self.state.save()
        return count
