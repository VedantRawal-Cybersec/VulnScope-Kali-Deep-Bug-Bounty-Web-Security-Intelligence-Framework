#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import time
from collections import deque
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from core.http_client_v2 import ResponseRecord, SafeHttpClientV2
from core.scan_state import ParamRecord, ScanState, _param_kind, _risk_score
from core.test_engine import TestEngine

SAFE_CHECK_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/admin",
    "/login",
    "/dashboard",
    "/api",
    "/debug",
    "/config.json",
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

ROUTE_RE = re.compile(r"(?P<quote>['\"])(?P<route>/(?:api/)?[A-Za-z0-9_./?=&:%#-]{2,180})(?P=quote)")
FETCH_RE = re.compile(r"(?:fetch|axios\.(?:get|post|request)|open)\s*\(\s*['\"]([^'\"]{2,240})['\"]", re.I)
SOURCE_MAP_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)", re.I)
JS_MARKER_RE = re.compile(r"(?i)(api[_-]?key|token|secret|bearer|private[_-]?key|access[_-]?key)\s*[:=]\s*['\"]([^'\"]{8,160})['\"]")


def normalize_url(base: str, raw: str) -> str:
    raw = unescape(str(raw or "").strip())
    if not raw or raw.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
        return ""
    parsed = urlparse(urljoin(base, raw))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def masked(value: str) -> str:
    value = str(value or "")
    if len(value) <= 10:
        return "***"
    return value[:4] + "..." + value[-4:]


class SafeSurfaceEngine:
    """Deterministic surface mapper and safe evidence checks.

    This engine does not require AI. It uses existing same-scope HTTP guards,
    GET/HEAD requests, safe canary checks from TestEngine, and produces explicit
    report messages when paths, parameters, or findings are empty.
    """

    def __init__(self, *, state: ScanState, client: SafeHttpClientV2, tester: TestEngine, dashboard: Any | None = None, max_pages: int = 100, max_depth: int = 3, max_params: int = 250, mode: str = "safe-active") -> None:
        self.state = state
        self.client = client
        self.tester = tester
        self.dashboard = dashboard
        self.max_pages = max(1, int(max_pages))
        self.max_depth = max(0, int(max_depth))
        self.max_params = max(1, int(max_params))
        self.mode = mode
        self.host = self.state.host.lower()
        self.fetched: dict[str, ResponseRecord] = {}
        self.forms: list[dict[str, Any]] = []
        self.js_files: list[str] = []
        self.routes: list[str] = []
        self.paths: set[str] = set()
        self.finding_keys: set[str] = set()
        self.errors: list[dict[str, str]] = []

    def same_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return bool(host and (host == self.host or host.endswith("." + self.host)))

    def dash(self, phase: str, action: str, *, url: str = "", param: str = "", evidence: str = "", progress: int = 0) -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase=phase, phase_progress=progress, current_agent="SafeSurfaceEngine", current_tool="surface_mapper", action=action, endpoint=url or self.state.target, parameters=param, evidence=evidence[:1000], requests=self.state.stats.get("requests", 0), findings=len(self.state.findings), safety_status="authorized scope • GET/HEAD only • deterministic checks")
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", action)

    def add_url(self, url: str, *, depth: int, source: str) -> None:
        if not url or not self.same_scope(url):
            return
        self.paths.add(urlparse(url).path or "/")
        self.state.add_url(url, depth=depth, source=source)
        self.extract_query_params(url, source=source)

    def extract_query_params(self, url: str, *, source: str) -> int:
        query = parse_qs(urlparse(url).query, keep_blank_values=True)
        added = 0
        for name, values in query.items():
            kind = _param_kind(name)
            before = len(self.state.params)
            self.state.add_param(ParamRecord(url=url, name=name, value=values[0] if values else "", source=source, kind=kind, method="GET", risk_score=_risk_score(name, kind, url), notes=[f"GET parameter discovered from {source}"]))
            added += 1 if len(self.state.params) > before else 0
        return added

    def finding(self, *, title: str, status: str, severity: str, confidence: int, url: str, evidence: str, category: str, parameter: str = "", recommendation: str = "Review and harden this control.", impact: str = "This can increase security risk depending on context.") -> None:
        if not url or not evidence:
            return
        key = f"{title}|{url}|{parameter}|{evidence[:140]}"
        if key in self.finding_keys:
            return
        self.finding_keys.add(key)
        finding = {
            "id": "finding_" + str(len(self.state.findings) + 1).zfill(4),
            "title": title,
            "status": status,
            "severity": severity,
            "confidence": int(max(0, min(100, confidence))),
            "category": category,
            "affected_url": url,
            "path": urlparse(url).path or "/",
            "parameter": parameter or None,
            "method": "GET",
            "tool_name": "safe_surface_engine",
            "safe_probe_used": "deterministic-safe-check",
            "evidence": evidence[:3000],
            "impact": impact,
            "recommendation": recommendation,
            "reproduction_steps": [f"Request `{url}` within the authorized scope.", "Review the response evidence shown in this finding."],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self.state.add_finding(finding)
        if self.dashboard is not None and hasattr(self.dashboard, "add_finding"):
            self.dashboard.add_finding(title, impact, severity, url=url, parameter=parameter or "—", test_string="deterministic-safe-check", evidence=evidence[:1000], confidence=f"{confidence}%", reproduction="\n".join(finding["reproduction_steps"]), confirmation=status.lower())

    def fetch(self, url: str, *, purpose: str) -> ResponseRecord | None:
        if not self.same_scope(url):
            return None
        if url in self.fetched:
            return self.fetched[url]
        self.dash("Deterministic Discovery", "Fetching URL", url=url, progress=15)
        response = self.client.get(url, purpose=purpose)
        self.fetched[url] = response
        record = self.state.urls.get(url) or self.state.add_url(url, source=purpose)
        record.status = "done" if response.ok else "failed"
        record.status_code = response.status_code
        record.content_type = response.headers.get("Content-Type", "")
        record.last_seen_at = time.time()
        record.error = response.error
        if response.error:
            self.errors.append({"url": url, "error": response.error})
            self.state.add_event("WARNING", "fetch failed", url=url, error=response.error)
        return response

    def parse_robots(self) -> None:
        response = self.fetch(urljoin(self.state.target.rstrip("/") + "/", "robots.txt"), purpose="robots")
        if not response or not response.ok:
            self.state.add_event("INFO", "robots unavailable")
            return
        for line in response.text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key in {"allow", "disallow"} and value and value != "/":
                self.add_url(normalize_url(response.url, value), depth=0, source="robots")
            elif key == "sitemap" and value:
                self.parse_sitemap(normalize_url(response.url, value))

    def parse_sitemap(self, url: str | None = None, seen: set[str] | None = None) -> None:
        seen = seen or set()
        url = url or urljoin(self.state.target.rstrip("/") + "/", "sitemap.xml")
        if not url or url in seen or not self.same_scope(url):
            return
        seen.add(url)
        response = self.fetch(url, purpose="sitemap")
        if not response or not response.ok:
            self.state.add_event("INFO", "sitemap unavailable", url=url)
            return
        for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", response.text or "", re.I):
            loc_url = normalize_url(response.url, loc)
            if not loc_url or not self.same_scope(loc_url):
                continue
            if loc_url.endswith(".xml"):
                self.parse_sitemap(loc_url, seen)
            else:
                self.add_url(loc_url, depth=0, source="sitemap")

    def parse_html(self, response: ResponseRecord, depth: int) -> list[str]:
        soup = BeautifulSoup(response.text or "", "html.parser")
        links: list[str] = []
        for tag in soup.find_all(True):
            for attr in ["href", "src", "action", "content"]:
                raw = tag.get(attr)
                if not raw:
                    continue
                if tag.name == "meta" and attr == "content" and "url=" in str(raw).lower():
                    raw = str(raw).split("url=", 1)[-1]
                url = normalize_url(response.url, str(raw))
                if url and self.same_scope(url):
                    links.append(url)
                    if tag.name == "script" and attr == "src":
                        self.js_files.append(url)
        self.extract_forms(response, soup)
        self.extract_routes(response.url, response.text or "", source="inline-js")
        return links

    def extract_forms(self, response: ResponseRecord, soup: BeautifulSoup) -> None:
        for form in soup.find_all("form"):
            method = str(form.get("method") or "GET").upper()
            action = normalize_url(response.url, form.get("action") or response.url)
            fields: list[dict[str, str]] = []
            for field in form.find_all(["input", "select", "textarea", "button"]):
                name = str(field.get("name") or "").strip()
                if not name:
                    continue
                ftype = str(field.get("type") or field.name or "text").lower()
                value = str(field.get("value") or self.default_value(name, ftype))
                fields.append({"name": name, "type": ftype, "value": value})
                if method == "GET" and action and self.same_scope(action):
                    form_url = self.url_with_param(action, name, value)
                    self.add_url(form_url, depth=0, source="get-form")
            self.forms.append({"url": response.url, "method": method, "action": action, "fields": fields})

    @staticmethod
    def default_value(name: str, ftype: str) -> str:
        lname = name.lower()
        if lname in {"q", "query", "search", "keyword"}:
            return "test"
        if lname in {"id", "page", "cat", "product", "item"} or lname.endswith("_id"):
            return "1"
        if ftype == "email":
            return "test@example.com"
        return "test"

    @staticmethod
    def url_with_param(url: str, name: str, value: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[name] = [value]
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(query, doseq=True), ""))

    def extract_routes(self, base_url: str, text: str, *, source: str) -> None:
        for raw in {m.group("route") for m in ROUTE_RE.finditer(text or "")} | {m.group(1) for m in FETCH_RE.finditer(text or "")}:
            url = normalize_url(base_url, raw)
            if url and self.same_scope(url):
                self.routes.append(url)
                self.add_url(url, depth=0, source=source)

    def crawl(self) -> None:
        self.parse_robots()
        self.parse_sitemap()
        for path in SAFE_CHECK_PATHS:
            self.add_url(urljoin(self.state.target.rstrip("/") + "/", path.lstrip("/")), depth=0, source="safe-checklist")
        queue: deque[tuple[str, int]] = deque([(self.state.target, 0)])
        for url, record in list(self.state.urls.items()):
            queue.append((url, min(record.depth, self.max_depth)))
        while queue and len(self.fetched) < self.max_pages:
            url, depth = queue.popleft()
            if url in self.fetched or depth > self.max_depth or not self.same_scope(url):
                continue
            response = self.fetch(url, purpose="deterministic-crawl")
            if not response or not response.ok:
                continue
            self.extract_query_params(response.url, source="crawler")
            ctype = response.headers.get("Content-Type", "").lower()
            if "html" in ctype or "<html" in (response.text or "")[:600].lower():
                for link in self.parse_html(response, depth):
                    if link not in self.state.urls:
                        self.add_url(link, depth=depth + 1, source="html")
                        queue.append((link, depth + 1))
            elif response.url.endswith(".js") or "javascript" in ctype:
                self.js_files.append(response.url)
                self.extract_routes(response.url, response.text or "", source="js-file")
        self.fetch_js_files()

    def fetch_js_files(self) -> None:
        for js_url in list(dict.fromkeys(self.js_files))[:80]:
            response = self.fetch(js_url, purpose="javascript")
            if not response or not response.ok:
                continue
            self.extract_routes(js_url, response.text or "", source="js-file")
            self.check_js_markers(response)
            self.check_source_map(response)

    def passive_checks(self) -> None:
        root = self.fetched.get(self.state.target) or self.fetch(self.state.target, purpose="passive-root")
        if root and root.ok:
            self.check_headers(root)
            self.check_cookies(root)
            self.check_cors(root)
            self.check_csp(root)

    def check_headers(self, response: ResponseRecord) -> None:
        missing = [name for name in SECURITY_HEADERS if name not in response.headers]
        if missing:
            self.finding(title="Missing Security Headers", status="Confirmed", severity="Low" if len(missing) <= 3 else "Medium", confidence=90, url=response.url, category="Security Headers", evidence="Missing response headers: " + ", ".join(missing), recommendation="Add appropriate browser security headers for this application.", impact="Missing browser security headers can reduce client-side hardening.")

    def check_cookies(self, response: ResponseRecord) -> None:
        cookie = response.headers.get("Set-Cookie", "")
        if not cookie:
            return
        low = cookie.lower()
        issues = []
        if "secure" not in low:
            issues.append("Secure flag missing")
        if "httponly" not in low:
            issues.append("HttpOnly flag missing")
        if "samesite" not in low:
            issues.append("SameSite flag missing")
        if issues:
            sample = re.sub(r"=([^;]{3,})", "=***", cookie[:500])
            self.finding(title="Cookie Security Flags Missing", status="Confirmed", severity="Medium", confidence=88, url=response.url, category="Cookie Security", evidence="; ".join(issues) + f". Cookie sample: {sample}", recommendation="Set Secure, HttpOnly, and SameSite where applicable.", impact="Weak cookie attributes can increase browser-side and transport risk.")

    def check_cors(self, response: ResponseRecord) -> None:
        original = dict(self.client.session.headers)
        try:
            self.client.session.headers.update({"Origin": "https://vulnscope-safe-origin.example"})
            cors = self.client.get(response.url, purpose="cors-check", allow_redirects=False)
        finally:
            self.client.session.headers.clear()
            self.client.session.headers.update(original)
        acao = cors.headers.get("Access-Control-Allow-Origin", "") if cors else ""
        acc = cors.headers.get("Access-Control-Allow-Credentials", "") if cors else ""
        if acao == "*" or acao == "https://vulnscope-safe-origin.example":
            self.finding(title="Permissive CORS Configuration", status="Confirmed", severity="High" if acc.lower() == "true" else "Medium", confidence=90, url=response.url, category="CORS", evidence=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acc or 'not set'}", recommendation="Restrict CORS to trusted application origins.", impact="Broad CORS can expose browser-readable responses to untrusted origins.")

    def check_csp(self, response: ResponseRecord) -> None:
        csp = response.headers.get("Content-Security-Policy", "")
        if not csp:
            return
        weak = [token for token in ["unsafe-inline", "unsafe-eval", "*", "data:"] if token in csp]
        for directive in ["object-src", "base-uri", "frame-ancestors"]:
            if directive not in csp:
                weak.append("missing " + directive)
        if weak:
            self.finding(title="Weak Content Security Policy", status="Confirmed", severity="Low", confidence=82, url=response.url, category="CSP", evidence="Weak CSP indicators: " + ", ".join(sorted(set(weak))), recommendation="Tighten CSP directives and remove broad script allowances where possible.", impact="Weak CSP can reduce browser-side containment.")

    def check_js_markers(self, response: ResponseRecord) -> None:
        hits = []
        for match in JS_MARKER_RE.finditer(response.text or ""):
            hits.append(f"{match.group(1)}={masked(match.group(2))}")
        if hits:
            self.finding(title="JavaScript Exposure Indicator", status="Potential", severity="Medium", confidence=75, url=response.url, category="JavaScript Review", evidence="; ".join(sorted(set(hits)))[:2000], recommendation="Review client-side JavaScript and remove sensitive configuration from public assets.", impact="Client-side files may reveal implementation details or accidentally exposed tokens.")

    def check_source_map(self, response: ResponseRecord) -> None:
        for match in SOURCE_MAP_RE.finditer(response.text or ""):
            map_url = normalize_url(response.url, match.group(1).strip())
            if not map_url or not self.same_scope(map_url):
                continue
            mapped = self.fetch(map_url, purpose="source-map-check")
            if mapped and mapped.ok and ("sources" in mapped.text[:2000] or mapped.url.endswith(".map")):
                self.finding(title="Readable JavaScript Source Map", status="Confirmed", severity="Low", confidence=90, url=map_url, category="Source Map", evidence="Source map returned HTTP 200 and contains readable source-map indicators.", recommendation="Avoid publishing source maps for production bundles unless intentionally public.", impact="Readable source maps can expose original source structure.")

    def safe_active_checks(self) -> None:
        if self.mode == "passive":
            self.state.add_event("INFO", "safe-active checks skipped in passive mode")
            return
        params = self.state.queued_params(limit=min(self.max_params, 120))
        if not params:
            self.state.add_event("INFO", "No safe query parameters or GET inputs were discovered within the selected scan scope.")
            return
        for param in params:
            self.dash("Safe Active Testing", "Running safe deterministic parameter checks", url=param.url, param=param.name, progress=70)
            self.tester.run_test(param, "baseline")
            self.tester.run_test(param, "reflection_canary")
            if param.kind in {"route-like", "reference-like"}:
                self.tester.run_test(param, "redirect_review")
            self.tester.run_test(param, "classification_review")

    def write_reports(self) -> dict[str, str]:
        out = self.state.out_dir
        out.mkdir(parents=True, exist_ok=True)
        surface = {
            "target": self.state.target,
            "urls": sorted(self.state.urls.keys()),
            "paths": sorted(self.paths),
            "parameters": [vars(p) for p in self.state.params.values()],
            "forms": self.forms,
            "javascript_files": sorted(set(self.js_files)),
            "routes": sorted(set(self.routes)),
            "errors": self.errors,
            "messages": {
                "paths": "No internal paths were discovered within the selected scan scope." if not self.paths else "Internal paths discovered.",
                "parameters": "No safe query parameters or GET inputs were discovered within the selected scan scope." if not self.state.params else "Safe query parameters or GET inputs discovered.",
                "findings": "No confirmed vulnerabilities were detected in the selected safe assessment scope." if not self.state.findings else "Findings were detected and recorded.",
            },
        }
        json_path = out / "surface-map.json"
        md_path = out / "surface-map.md"
        json_path.write_text(json.dumps(surface, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# VulnScope Surface Map", "", f"Target: `{self.state.target}`", "", "## Summary", "", f"- URLs: `{len(surface['urls'])}`", f"- Paths: `{len(surface['paths'])}`", f"- Parameters: `{len(surface['parameters'])}`", f"- Forms: `{len(self.forms)}`", f"- JavaScript files: `{len(set(self.js_files))}`", f"- Routes: `{len(set(self.routes))}`", f"- Findings: `{len(self.state.findings)}`", "", "## Messages", ""]
        for value in surface["messages"].values():
            lines.append(f"- {value}")
        lines.extend(["", "## Parameters", ""])
        if not surface["parameters"]:
            lines.append("No safe query parameters or GET inputs were discovered within the selected scan scope.")
        else:
            for p in surface["parameters"][:200]:
                lines.append(f"- `{p['method']}` `{p['name']}` kind=`{p['kind']}` risk=`{p['risk_score']}` url=`{p['url']}`")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"surface_map_json": str(json_path), "surface_map_md": str(md_path)}

    def run_all(self) -> dict[str, Any]:
        self.state.add_event("INFO", "safe surface engine started", mode=self.mode)
        self.crawl()
        self.passive_checks()
        self.safe_active_checks()
        reports = self.write_reports()
        self.state.stats["safe_surface_urls"] = len(self.state.urls)
        self.state.stats["safe_surface_params"] = len(self.state.params)
        self.state.stats["safe_surface_forms"] = len(self.forms)
        self.state.stats["safe_surface_js_files"] = len(set(self.js_files))
        self.state.stats["safe_surface_routes"] = len(set(self.routes))
        self.state.add_event("INFO", "safe surface engine completed", **reports)
        self.state.save()
        return {"ok": True, "reports": reports, "urls": len(self.state.urls), "paths": len(self.paths), "params": len(self.state.params), "forms": len(self.forms), "javascript_files": len(set(self.js_files)), "routes": len(set(self.routes)), "findings": len(self.state.findings), "errors": len(self.errors)}
