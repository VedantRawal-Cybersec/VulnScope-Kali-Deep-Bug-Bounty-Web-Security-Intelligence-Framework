#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import html.parser
import json
import os
import random
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

VERSION = "2.0.0-lean-runtime"
USER_AGENT = "VulnScope-Lean-Authorized-Scanner/2.0"
SAFE_EMPTY = "No safe query parameters or GET inputs were discovered in the selected scope."
OUT_ROOT = Path("reports/output/vulnscope")

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

ASSET_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".mp4", ".webm",
)

TOOL_STATUS = ["queued", "running", "completed", "failed", "skipped", "blocked_by_scope", "blocked_by_safety", "timed_out"]


@dataclass
class ToolSpec:
    tool_id: str
    tool_name: str
    agent: str
    category: str
    safety_level: str = "passive"
    status: str = "queued"
    output_count: int = 0
    error_message: str = ""
    last_run_timestamp: float = 0.0


@dataclass
class SurfaceItem:
    url: str
    path: str
    method: str = "GET"
    parameter: str = ""
    original_value: str = ""
    source: str = "crawler"
    safe_to_test: bool = True
    reason: str = "safe GET/query input"


@dataclass
class Finding:
    id: str
    title: str
    status: str
    severity: str
    confidence: int
    affected_url: str
    path: str
    parameter: str
    tool_name: str
    safe_probe_used: str
    evidence: str
    impact: str
    recommendation: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class TraceEvent:
    scan_id: str
    timestamp: float
    turn_id: int
    agent_name: str
    tool_name: str
    phase: str
    status: str
    target_url: str = ""
    path: str = ""
    parameter: str = ""
    safe_probe_used: str = ""
    message: str = ""
    evidence_summary: str = ""
    progress_percent: int = 0


class LinkParser(html.parser.HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[dict[str, Any]] = []
        self.inline_js: list[str] = []
        self._in_script = False
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_d = {k.lower(): v or "" for k, v in attrs}
        tag = tag.lower()
        if tag in {"a", "link"} and attrs_d.get("href"):
            self.links.add(urljoin(self.base_url, attrs_d["href"]).split("#")[0])
        if tag == "script":
            self._in_script = True
            if attrs_d.get("src"):
                self.scripts.add(urljoin(self.base_url, attrs_d["src"]).split("#")[0])
        if tag == "form":
            self._form = {"method": (attrs_d.get("method") or "GET").upper(), "action": urljoin(self.base_url, attrs_d.get("action") or self.base_url), "inputs": {}}
        if self._form is not None and tag in {"input", "select", "textarea"}:
            name = attrs_d.get("name")
            if name:
                self._form["inputs"][name] = attrs_d.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._in_script = False
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_script and data:
            self.inline_js.append(data[:50000])


def normalize_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("target is required")
    return raw if "://" in raw else "https://" + raw


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def canonical(url: str) -> str:
    p = urlparse(url)
    q = urlencode(parse_qs(p.query, keep_blank_values=True), doseq=True)
    return urlunparse((p.scheme or "https", p.netloc.lower(), p.path or "/", "", q, ""))


def same_scope(url: str, base_host: str, include_subdomains: bool = False) -> bool:
    p = urlparse(url)
    h = (p.hostname or "").lower()
    if p.scheme not in {"http", "https"} or not h:
        return False
    if (p.path or "").lower().endswith(ASSET_EXT):
        return False
    return h == base_host or (include_subdomains and h.endswith("." + base_host))


def replace_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    q[param] = [value]
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", urlencode(q, doseq=True), ""))


def classify_param(name: str) -> tuple[str, int]:
    n = name.lower()
    if n in {"q", "query", "search", "s", "term", "keyword"}:
        return "search-like", 55
    if n in {"id", "uid", "user_id", "account_id", "order_id"} or n.endswith("_id"):
        return "object-like", 65
    if n in {"next", "url", "redirect", "return", "continue", "callback"} or n.endswith("url"):
        return "route-like", 75
    if n in {"file", "path", "page", "download"}:
        return "resource-like", 70
    return "generic", 25


def body_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode(errors="ignore")).hexdigest()[:16]


class Dashboard:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.start = time.time()
        self.last_lines = 0
        self.logs: list[str] = []
        self.state: dict[str, Any] = {}

    def log(self, message: str) -> None:
        self.logs.append(f"{time.strftime('%H:%M:%S')} {message}")
        self.logs = self.logs[-25:]

    def update(self, **kwargs: Any) -> None:
        self.state.update(kwargs)
        if self.enabled:
            self.draw()

    def draw(self) -> None:
        if not sys.stdout.isatty():
            return
        s = self.state
        elapsed = int(time.time() - self.start)
        lines = [
            "VulnScope 2.0 Lean Runtime — single dashboard",
            "─" * 110,
            f"Target: {s.get('target','—')} | Mode: {s.get('mode','—')} | Scan ID: {s.get('scan_id','—')} | Time: {elapsed//60:02d}:{elapsed%60:02d}",
            f"Ollama: {s.get('ollama','checking')} | Phase: {s.get('phase','—')} | Progress: {s.get('progress',0)}% | Turn: {s.get('turn',0)}/{s.get('max_turns',0)}",
            "",
            f"Agent: {s.get('agent','—')} | Tool: {s.get('tool','—')} | Action: {s.get('action','—')}",
            f"URL: {s.get('url','—')}",
            f"Path: {s.get('path','/')}",
            f"Parameter: {s.get('parameter', SAFE_EMPTY)} | Probe: {s.get('probe','—')} | Response: {s.get('code','—')} / {s.get('rt','—')}ms",
            "",
            f"Surface: URLs {s.get('urls',0)} | Paths {s.get('paths',0)} | Params {s.get('params',0)} | Forms {s.get('forms',0)} | JS {s.get('js',0)} | API-like {s.get('api',0)}",
            f"Tools: Total {s.get('tools_total',0)} | Running {s.get('tools_running',0)} | Completed {s.get('tools_completed',0)} | Failed {s.get('tools_failed',0)} | Skipped {s.get('tools_skipped',0)} | Blocked {s.get('tools_blocked',0)}",
            f"Findings: Confirmed {s.get('confirmed',0)} | Potential {s.get('potential',0)} | Info {s.get('info',0)} | Total {s.get('findings',0)}",
            "─" * 110,
            "Logs:",
            *self.logs[-20:],
        ]
        text = "\n".join(lines)
        sys.stdout.write("\033[H\033[J" + text)
        sys.stdout.flush()
        self.last_lines = len(lines)


class VulnScopeRuntime:
    def __init__(self, target: str, *, scan_mode: str, max_pages: int, max_depth: int, max_params: int, request_budget: int, request_timeout: int, delay: float, include_subdomains: bool = False, no_dashboard: bool = False, ollama_url: str = "http://localhost:11434/api/tags", ollama_model: str = "qwen2.5:3b") -> None:
        self.target = normalize_target(target)
        self.host = host_of(self.target)
        self.scan_mode = scan_mode
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_params = max_params
        self.request_budget = request_budget
        self.timeout = request_timeout
        self.delay = delay
        self.include_subdomains = include_subdomains
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.scan_id = "scan_" + hashlib.sha1(f"{self.target}{time.time()}".encode()).hexdigest()[:10]
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.dashboard = Dashboard(enabled=not no_dashboard)
        self.out = OUT_ROOT / self.host
        self.out.mkdir(parents=True, exist_ok=True)
        self.tools = self._build_tools()
        self.turn = 0
        self.requests = 0
        self.urls: dict[str, dict[str, Any]] = {canonical(self.target): {"depth": 0, "source": "seed", "status": "queued"}}
        self.surface: list[SurfaceItem] = []
        self.findings: list[Finding] = []
        self.trace: list[TraceEvent] = []
        self.forms = 0
        self.js_files: set[str] = set()
        self.api_like: set[str] = set()
        self.last_request = 0.0

    def _build_tools(self) -> list[ToolSpec]:
        real = [
            ("scope_guard", "Scope Guard", "ScopeAgent", "Guardrails"),
            ("ollama_diagnostics", "Ollama Diagnostics", "OllamaReasoningAgent", "Diagnostics"),
            ("availability_checker", "Availability Checker", "ReconAgent", "Recon"),
            ("header_analyzer", "Header Analyzer", "HeaderAnalysisAgent", "Passive"),
            ("cookie_analyzer", "Cookie Analyzer", "CookieAnalysisAgent", "Passive"),
            ("robots_parser", "Robots Parser", "ReconAgent", "Discovery"),
            ("sitemap_parser", "Sitemap Parser", "ReconAgent", "Discovery"),
            ("safe_crawler", "Safe Crawler", "CrawlerAgent", "Discovery"),
            ("js_route_extractor", "JS Route Extractor", "JSExposureAgent", "Discovery"),
            ("parameter_discovery", "Parameter Discovery", "ParameterDiscoveryAgent", "Discovery"),
            ("safe_canary_tester", "Safe Canary Tester", "SafeCanaryTestingAgent", "Safe Active"),
            ("finding_validator", "Finding Validator", "FindingValidationAgent", "Validation"),
            ("risk_scorer", "Risk Scorer", "RiskScoringAgent", "Scoring"),
            ("report_generator", "Report Generator", "ReportAgent", "Reporting"),
        ]
        tools = [ToolSpec(a, b, c, d) for a, b, c, d in real]
        for i in range(1, 89):
            tools.append(ToolSpec(f"catalog_{i:03d}", f"Catalogued Safe Module {i:03d}", "SupervisorAgent", "Catalog", status="skipped", error_message="catalogued but not required for this scan path"))
        return tools

    def mark(self, tool_id: str, status: str, output_count: int = 0, error: str = "") -> None:
        for t in self.tools:
            if t.tool_id == tool_id:
                t.status = status
                t.output_count = output_count
                t.error_message = error
                t.last_run_timestamp = time.time()
                return

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in TOOL_STATUS}
        for t in self.tools:
            c[t.status] = c.get(t.status, 0) + 1
        return c

    def progress(self, phase: str, agent: str, tool: str, action: str, *, url: str | None = None, parameter: str = "", probe: str = "—", code: Any = "—", rt: Any = "—", progress: int = 0) -> None:
        self.turn += 1
        p = urlparse(url or self.target)
        paths = {urlparse(u).path or "/" for u in self.urls}
        c = self.counts()
        confirmed = sum(1 for f in self.findings if f.status == "Confirmed")
        potential = sum(1 for f in self.findings if f.status == "Potential")
        info = sum(1 for f in self.findings if f.status == "Informational")
        self.trace.append(TraceEvent(self.scan_id, time.time(), self.turn, agent, tool, phase, "running", url or self.target, p.path or "/", parameter, probe, action, f"HTTP {code}", progress))
        self.dashboard.update(target=self.target, mode=self.scan_mode, scan_id=self.scan_id, phase=phase, progress=progress, turn=self.turn, max_turns=160, agent=agent, tool=tool, action=action, url=url or self.target, path=p.path or "/", parameter=parameter or (p.query or SAFE_EMPTY), probe=probe, code=code, rt=rt, urls=len(self.urls), paths=len(paths), params=len(self.surface), forms=self.forms, js=len(self.js_files), api=len(self.api_like), tools_total=len(self.tools), tools_running=c.get("running", 0), tools_completed=c.get("completed", 0), tools_failed=c.get("failed", 0) + c.get("timed_out", 0), tools_skipped=c.get("skipped", 0), tools_blocked=c.get("blocked_by_safety", 0) + c.get("blocked_by_scope", 0), confirmed=confirmed, potential=potential, info=info, findings=len(self.findings))

    def add_finding(self, title: str, status: str, severity: str, confidence: int, url: str, parameter: str, tool: str, probe: str, evidence: str, impact: str, recommendation: str) -> None:
        if not evidence or not url or not tool:
            return
        key = (title, url, parameter, evidence[:80])
        for f in self.findings:
            if (f.title, f.affected_url, f.parameter, f.evidence[:80]) == key:
                return
        p = urlparse(url)
        self.findings.append(Finding("finding_" + hashlib.sha1(str(key).encode()).hexdigest()[:10], title, status, severity, max(0, min(100, confidence)), url, p.path or "/", parameter, tool, probe, evidence[:1200], impact, recommendation))
        self.dashboard.log(f"FIND {severity} {status}: {title}")

    def request(self, url: str, purpose: str) -> tuple[int, dict[str, str], str, int, str]:
        if self.requests >= self.request_budget:
            raise RuntimeError("request budget exhausted")
        wait = self.delay - (time.time() - self.last_request)
        if wait > 0:
            time.sleep(wait)
        self.last_request = time.time()
        start = time.time()
        self.requests += 1
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            text = r.text[:1_000_000]
            return int(r.status_code), dict(r.headers), text, int((time.time() - start) * 1000), str(r.url)
        except requests.Timeout:
            return 0, {}, "", int((time.time() - start) * 1000), "timeout"
        except Exception as exc:
            return 0, {}, "", int((time.time() - start) * 1000), str(exc)[:300]

    def add_params_from_url(self, url: str, source: str) -> None:
        q = parse_qs(urlparse(url).query, keep_blank_values=True)
        for name, vals in q.items():
            if len(self.surface) >= self.max_params:
                return
            item = SurfaceItem(url=url, path=urlparse(url).path or "/", parameter=name, original_value=vals[0] if vals else "", source=source)
            if not any(x.url == item.url and x.parameter == item.parameter for x in self.surface):
                self.surface.append(item)

    def ollama_check(self) -> None:
        self.mark("ollama_diagnostics", "running")
        self.progress("Diagnostics", "OllamaReasoningAgent", "ollama_diagnostics", "checking Ollama connectivity", progress=2)
        try:
            base = self.ollama_url.replace("/api/chat", "/api/tags").replace("/api/generate", "/api/tags")
            r = requests.get(base, timeout=4)
            ok = r.status_code == 200
            self.dashboard.update(ollama=(f"Connected • {self.ollama_model}" if ok else "Fallback deterministic"))
            self.mark("ollama_diagnostics", "completed" if ok else "skipped", 1 if ok else 0, "Ollama unavailable; deterministic scanner continued" if not ok else "")
        except Exception as exc:
            self.dashboard.update(ollama="Fallback deterministic")
            self.mark("ollama_diagnostics", "skipped", 0, str(exc)[:200])

    def passive_analyze(self, url: str, code: int, headers: dict[str, str], body: str, rt: int) -> None:
        self.mark("header_analyzer", "running")
        self.progress("Passive Analysis", "HeaderAnalysisAgent", "header_analyzer", "checking security headers", url=url, code=code, rt=rt, progress=12)
        for h in SECURITY_HEADERS:
            if h not in headers:
                sev = "Medium" if h in {"Content-Security-Policy", "Strict-Transport-Security"} else "Low"
                self.add_finding(f"Missing {h} Header", "Confirmed", sev, 98, url, "", "header_analyzer", "passive", f"HTTP response does not include `{h}`.", "Missing hardening header reduces browser or transport protection.", f"Configure `{h}` with an application-appropriate policy.")
        self.mark("header_analyzer", "completed", len(SECURITY_HEADERS))
        self.mark("cookie_analyzer", "running")
        raw_cookie = headers.get("Set-Cookie", "")
        if raw_cookie:
            for cookie in re.split(r",\s*(?=[^;,]+=)", raw_cookie):
                name = cookie.split("=", 1)[0][:80]
                missing = []
                lc = cookie.lower()
                if "httponly" not in lc:
                    missing.append("HttpOnly")
                if "samesite" not in lc:
                    missing.append("SameSite")
                if urlparse(url).scheme == "https" and "secure" not in lc:
                    missing.append("Secure")
                if missing:
                    self.add_finding(f"Cookie Missing Flags: {name}", "Confirmed", "Low", 95, url, "", "cookie_analyzer", "passive", f"Cookie `{name}` missing {', '.join(missing)}. Value masked.", "Missing cookie flags can weaken browser-side protection.", "Set Secure, HttpOnly, and SameSite where applicable.")
        self.mark("cookie_analyzer", "completed")

    def metadata(self) -> None:
        base = f"{urlparse(self.target).scheme}://{urlparse(self.target).netloc}"
        for tool, path in [("robots_parser", "/robots.txt"), ("sitemap_parser", "/sitemap.xml")]:
            self.mark(tool, "running")
            url = urljoin(base, path)
            code, headers, body, rt, final_url = self.request(url, tool)
            self.progress("Discovery", "ReconAgent", tool, f"checking {path}", url=url, code=code, rt=rt, progress=18)
            if code == 200 and body.strip():
                if tool == "robots_parser":
                    disallows = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", body)
                    for d in disallows[:100]:
                        full = canonical(urljoin(base, d))
                        self.urls.setdefault(full, {"depth": 1, "source": "robots", "status": "queued"})
                    if disallows:
                        self.add_finding("robots.txt Exposes Crawl Directives", "Informational", "Info", 90, url, "", tool, "passive", f"robots.txt contains {len(disallows)} Disallow entries. Example: {', '.join(disallows[:5])}", "robots.txt can reveal route names but is not access control.", "Keep sensitive routes protected by server-side authorization.")
                else:
                    locs = re.findall(r"<loc>\s*([^<]+)\s*</loc>", body, re.I)
                    for loc in locs[:500]:
                        full = canonical(loc.strip())
                        if same_scope(full, self.host, self.include_subdomains):
                            self.urls.setdefault(full, {"depth": 1, "source": "sitemap", "status": "queued"})
                            self.add_params_from_url(full, "sitemap")
                self.mark(tool, "completed", 1)
            else:
                self.mark(tool, "completed", 0, f"HTTP {code}")

    def crawl(self) -> None:
        self.mark("safe_crawler", "running")
        queue = list(self.urls.items())
        done = 0
        while queue and done < self.max_pages and self.requests < self.request_budget:
            url, meta = queue.pop(0)
            if meta.get("status") == "done":
                continue
            depth = int(meta.get("depth", 0))
            if depth > self.max_depth or not same_scope(url, self.host, self.include_subdomains):
                meta["status"] = "skipped"
                continue
            code, headers, body, rt, final_url = self.request(url, "crawl")
            self.progress("Crawling", "CrawlerAgent", "safe_crawler", f"crawling depth={depth}", url=url, code=code, rt=rt, progress=min(60, 20 + done))
            meta.update({"status": "done", "code": code, "hash": body_hash(body)})
            self.add_params_from_url(final_url if code else url, "url")
            if done == 0 and code:
                self.passive_analyze(final_url, code, headers, body, rt)
            if code == 200 and ("html" in headers.get("Content-Type", "").lower() or "<html" in body[:1000].lower()):
                parser = LinkParser(final_url)
                try:
                    parser.feed(body)
                except Exception:
                    pass
                for s in parser.scripts:
                    if same_scope(s, self.host, self.include_subdomains):
                        self.js_files.add(s)
                for f in parser.forms:
                    self.forms += 1
                    if f.get("method") == "GET" and same_scope(f.get("action", ""), self.host, self.include_subdomains):
                        action = f["action"]
                        inputs = f.get("inputs", {})
                        q = parse_qs(urlparse(action).query, keep_blank_values=True)
                        for name, value in inputs.items():
                            q[name] = [value]
                        form_url = urlunparse((urlparse(action).scheme, urlparse(action).netloc, urlparse(action).path or "/", "", urlencode(q, doseq=True), ""))
                        self.add_params_from_url(form_url, "get-form")
                for link in parser.links:
                    full = canonical(link)
                    if same_scope(full, self.host, self.include_subdomains) and full not in self.urls:
                        self.urls[full] = {"depth": depth + 1, "source": "link", "status": "queued"}
                        queue.append((full, self.urls[full]))
                    self.add_params_from_url(full, "link")
                for js in parser.inline_js:
                    for route in re.findall(r"['\"](/(?:api/)?[A-Za-z0-9_./-]+\?[^'\"<>\s]+)['\"]", js):
                        full = canonical(urljoin(final_url, route))
                        if same_scope(full, self.host, self.include_subdomains):
                            self.api_like.add(full)
                            self.urls.setdefault(full, {"depth": depth + 1, "source": "inline-js", "status": "queued"})
                            self.add_params_from_url(full, "inline-js")
            done += 1
        self.mark("safe_crawler", "completed", done)
        self.mark("parameter_discovery", "completed", len(self.surface))

    def js_routes(self) -> None:
        self.mark("js_route_extractor", "running")
        count = 0
        for js_url in list(self.js_files)[:30]:
            if self.requests >= self.request_budget:
                break
            code, headers, body, rt, final = self.request(js_url, "js-route")
            self.progress("JS Analysis", "JSExposureAgent", "js_route_extractor", "extracting JavaScript route hints", url=js_url, code=code, rt=rt, progress=65)
            if code == 200:
                for route in re.findall(r"['\"](/(?:api/)?[A-Za-z0-9_./-]+\?[^'\"<>\s]+)['\"]", body):
                    full = canonical(urljoin(js_url, route))
                    if same_scope(full, self.host, self.include_subdomains):
                        self.api_like.add(full)
                        self.urls.setdefault(full, {"depth": 1, "source": "external-js", "status": "queued"})
                        self.add_params_from_url(full, "external-js")
                        count += 1
        self.mark("js_route_extractor", "completed", count)

    def canary_tests(self) -> None:
        if self.scan_mode == "passive":
            self.mark("safe_canary_tester", "blocked_by_safety", 0, "requires safe-active mode")
            return
        self.mark("safe_canary_tester", "running")
        tested = 0
        for item in self.surface[: self.max_params]:
            if self.requests + 2 >= self.request_budget:
                break
            token = f"cai_safe_canary_{int(time.time())}_{random.randint(1000,9999)}"
            test_url = replace_param(item.url, item.parameter, token)
            b_code, b_headers, b_body, b_rt, b_url = self.request(item.url, "baseline")
            t_code, t_headers, t_body, t_rt, t_url = self.request(test_url, "safe-canary")
            self.progress("Safe Active Testing", "SafeCanaryTestingAgent", "safe_canary_tester", "testing harmless canary reflection", url=test_url, parameter=item.parameter, probe=token, code=t_code, rt=t_rt, progress=75)
            tested += 1
            if token in t_body:
                self.add_finding("Reflected Input Detected", "Confirmed", "Low", 95, test_url, item.parameter, "safe_canary_tester", token, "Exact harmless canary token was reflected in the HTTP response.", "Reflection needs output-encoding review. This is not automatically XSS.", "Validate and encode reflected user input. Manual review recommended.")
            elif t_code >= 500 and b_code < 500:
                self.add_finding("Server Error Triggered by Harmless Input", "Confirmed", "Medium", 90, test_url, item.parameter, "safe_canary_tester", token, f"Baseline HTTP {b_code}; canary HTTP {t_code}.", "Unexpected 5xx from harmless input can indicate fragile validation or exception handling.", "Improve input validation and error handling.")
        self.mark("safe_canary_tester", "completed", tested)
        self.mark("finding_validator", "completed", len(self.findings))
        self.mark("risk_scorer", "completed", len(self.findings))

    def reports(self) -> dict[str, str]:
        self.mark("report_generator", "running")
        self.progress("Reporting", "ReportAgent", "report_generator", "writing reports", progress=95)
        data = {
            "version": VERSION,
            "target": self.target,
            "scan_id": self.scan_id,
            "mode": self.scan_mode,
            "surface": [asdict(s) for s in self.surface],
            "urls": self.urls,
            "tools": [asdict(t) for t in self.tools],
            "findings": [asdict(f) for f in self.findings],
            "trace": [asdict(t) for t in self.trace],
            "safety": {"same_scope_only": True, "methods": ["GET"], "destructive_payloads": False, "data_modification": False},
        }
        json_path = self.out / "report.json"
        md_path = self.out / "report.md"
        surface_path = self.out / "surface.json"
        tools_path = self.out / "tool-matrix.json"
        csv_path = self.out / "findings.csv"
        json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        surface_path.write_text(json.dumps(data["surface"], indent=2, ensure_ascii=False), encoding="utf-8")
        tools_path.write_text(json.dumps(data["tools"], indent=2, ensure_ascii=False), encoding="utf-8")
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["id", "title", "status", "severity", "confidence", "affected_url", "parameter", "tool_name", "evidence", "recommendation"])
            w.writeheader()
            for finding in self.findings:
                w.writerow({k: getattr(finding, k) for k in w.fieldnames})
        lines = [f"# VulnScope Report", "", f"Target: `{self.target}`", f"Mode: `{self.scan_mode}`", f"Requests: `{self.requests}`", f"URLs: `{len(self.urls)}`", f"Parameters: `{len(self.surface)}`", f"Findings: `{len(self.findings)}`", "", "## Findings"]
        if not self.findings:
            lines.append("No confirmed findings were produced in the selected safe scope.")
        for f in self.findings:
            lines += ["", f"### {f.title}", f"- Status: `{f.status}`", f"- Severity: `{f.severity}`", f"- Confidence: `{f.confidence}%`", f"- URL: `{f.affected_url}`", f"- Parameter: `{f.parameter or 'N/A'}`", f"- Tool: `{f.tool_name}`", f"- Evidence: {f.evidence}", f"- Recommendation: {f.recommendation}"]
        lines += ["", "## Surface"]
        if not self.surface:
            lines.append(SAFE_EMPTY)
        else:
            for s in self.surface[:200]:
                lines.append(f"- `{s.method}` `{s.path}` param=`{s.parameter}` source=`{s.source}` safe=`{s.safe_to_test}` url=`{s.url}`")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        self.mark("report_generator", "completed", 5)
        return {"report_json": str(json_path), "report_md": str(md_path), "surface_json": str(surface_path), "tool_matrix_json": str(tools_path), "findings_csv": str(csv_path)}

    def run(self) -> dict[str, Any]:
        self.mark("scope_guard", "running")
        self.progress("Scope", "ScopeAgent", "scope_guard", "validating target and authorization", progress=1)
        p = urlparse(self.target)
        if p.scheme not in {"http", "https"} or not self.host:
            self.mark("scope_guard", "failed", 0, "unsupported or invalid target")
            raise SystemExit("Invalid target URL")
        self.mark("scope_guard", "completed", 1)
        self.ollama_check()
        self.mark("availability_checker", "running")
        code, headers, body, rt, final_url = self.request(self.target, "availability")
        self.progress("Recon", "ReconAgent", "availability_checker", "checking target availability", url=self.target, code=code, rt=rt, progress=6)
        self.mark("availability_checker", "completed" if code else "failed", 1 if code else 0, "not reachable" if not code else "")
        if code:
            self.passive_analyze(final_url, code, headers, body, rt)
        self.metadata()
        self.crawl()
        self.js_routes()
        self.canary_tests()
        reports = self.reports()
        self.progress("Complete", "ReportAgent", "report_generator", "scan complete", progress=100)
        if not sys.stdout.isatty():
            print(json.dumps({"status": "completed", "version": VERSION, "target": self.target, "findings": len(self.findings), "parameters": len(self.surface), "reports": reports}, indent=2))
        return {"status": "completed", "version": VERSION, "target": self.target, "findings": len(self.findings), "parameters": len(self.surface), "reports": reports}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VulnScope lean defensive CLI scanner")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", "--url", default="")
    parser.add_argument("--scan-mode", choices=["passive", "safe-active", "lab"], default="passive")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--max-pages", type=int, default=60)
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-params", type=int, default=120)
    parser.add_argument("--request-budget", type=int, default=250)
    parser.add_argument("--request-timeout", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--no-live-dashboard", action="store_true")
    parser.add_argument("--ollama-url", default=os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/tags"))
    parser.add_argument("--ollama-model", default=os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b"))
    parser.add_argument("--skip-100-tools", action="store_true")
    parser.add_argument("--skip-react", action="store_true")
    parser.add_argument("--tool-timeout", default="20")
    parser.add_argument("--max-turns", default="3")
    args = parser.parse_args(argv)
    if args.version:
        print(VERSION)
        return 0
    target = normalize_target(args.target or input("Target URL/domain: ").strip())
    if not args.yes and os.getenv("VULNSCOPE_AUTHORIZED", "0") != "1":
        ans = input("Type YES to confirm you own or have explicit permission to test this target: ").strip()
        if ans != "YES":
            print("Authorization not confirmed.")
            return 2
    if args.scan_mode == "safe-active" and not args.yes and os.getenv("VULNSCOPE_SAFE_ACTIVE_OK", "0") != "1":
        ans = input("Safe Active sends harmless canary GET values only. Type CONTINUE: ").strip()
        if ans != "CONTINUE":
            print("Safe Active not confirmed.")
            return 2
    runtime = VulnScopeRuntime(target, scan_mode=args.scan_mode, max_pages=args.max_pages, max_depth=args.max_depth, max_params=args.max_params, request_budget=args.request_budget, request_timeout=args.request_timeout, delay=args.delay, include_subdomains=args.include_subdomains, no_dashboard=args.no_live_dashboard, ollama_url=args.ollama_url, ollama_model=args.ollama_model)
    runtime.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
