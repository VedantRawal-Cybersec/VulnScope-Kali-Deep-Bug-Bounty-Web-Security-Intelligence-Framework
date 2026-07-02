#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target
from core.live_dashboard import LiveDashboard, target_components

VERSION = "1.0.0-real-safe-web-scanner"
DEFAULT_USER_AGENT = f"VulnScope-Safe-Web-Scanner/{VERSION}"
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
ASSET_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".zip",
    ".mp4", ".webm", ".mp3", ".avi", ".mov", ".css",
)
SENSITIVE_HINTS = (
    "login", "logout", "signin", "signup", "register", "reset", "password",
    "checkout", "payment", "cart", "order", "upload", "delete", "admin",
    "account", "profile", "billing", "invoice",
)
REDIRECT_PARAMS = {"next", "url", "redirect", "redirect_uri", "return", "return_url", "continue", "dest", "destination", "callback"}
URL_PARAMS = REDIRECT_PARAMS | {"uri", "link", "target", "site", "host", "domain", "endpoint", "callback_url"}
FILE_PARAMS = {"file", "path", "page", "template", "folder", "dir", "download", "document", "doc", "include"}
ID_PARAMS = {"id", "uid", "user", "user_id", "account", "account_id", "order", "order_id", "invoice", "invoice_id", "profile_id"}


def now() -> float:
    return time.time()


def clean(text: Any, limit: int = 240) -> str:
    value = str(text if text is not None else "")
    value = value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    value = re.sub(r"\s+", " ", value).strip()
    value = re.sub(r"(?i)(api[_-]?key|token|secret|password|passwd)=([^\s&]+)", r"\1=<redacted>", value)
    return value[:limit] + ("…" if len(value) > limit else "")


def safe_canary() -> str:
    return "vs_canary_" + uuid.uuid4().hex[:12]


def same_scope(url: str, base_host: str, include_subdomains: bool = False) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    base_host = base_host.lower()
    return host == base_host or (include_subdomains and host.endswith("." + base_host))


def canonicalize_url(raw: str) -> str:
    parsed = urlparse(raw)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query = urlencode(parse_qs(parsed.query, keep_blank_values=True), doseq=True)
    return urlunparse((scheme, netloc, path, "", query, ""))


def replace_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(query, doseq=True), ""))


def parameter_kind(name: str) -> str:
    value = name.lower().strip()
    if value in REDIRECT_PARAMS:
        return "redirect-like"
    if value in URL_PARAMS or value.endswith("url") or "callback" in value:
        return "url-like"
    if value in FILE_PARAMS or value.endswith("file") or value.endswith("path"):
        return "file-like"
    if value in ID_PARAMS or value.endswith("_id") or value == "id":
        return "id-like"
    if value in {"q", "query", "search", "keyword", "term", "s"}:
        return "search-like"
    return "generic"


def is_sensitive_path(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return any(hint in path for hint in SENSITIVE_HINTS)


def is_asset(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return path.endswith(ASSET_EXTENSIONS)


@dataclass
class FetchResult:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_ms: int
    content_type: str
    error: str = ""


@dataclass
class ParamTarget:
    url: str
    parameter: str
    value: str
    source: str
    kind: str
    method: str = "GET"


@dataclass
class FormTarget:
    page_url: str
    action_url: str
    method: str
    parameters: dict[str, str]


@dataclass
class Finding:
    id: str
    title: str
    status: str
    severity: str
    confidence: int
    category: str
    affected_url: str
    parameter: str | None
    evidence: str
    impact: str
    recommendation: str
    response_status: int | None = None
    response_time_ms: int | None = None
    safe_probe: str | None = None
    reproduction_steps: list[str] = field(default_factory=list)


class LinkFormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.inline_script = ""
        self.forms: list[FormTarget] = []
        self._in_script = False
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): v or "" for k, v in attrs}
        tag = tag.lower()
        if tag in {"a", "link"} and attr.get("href"):
            self.links.add(urljoin(self.base_url, attr["href"]).split("#")[0])
        if tag == "script":
            src = attr.get("src")
            if src:
                self.scripts.add(urljoin(self.base_url, src).split("#")[0])
            self._in_script = True
        if tag == "form":
            self._form = {
                "method": (attr.get("method") or "GET").upper(),
                "action": urljoin(self.base_url, attr.get("action") or self.base_url),
                "params": {},
            }
        if self._form is not None and tag in {"input", "textarea", "select"}:
            name = attr.get("name")
            if name:
                self._form["params"][name] = attr.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "script":
            self._in_script = False
        if tag == "form" and self._form is not None:
            self.forms.append(
                FormTarget(
                    page_url=self.base_url,
                    action_url=self._form["action"],
                    method=self._form["method"],
                    parameters=dict(self._form["params"]),
                )
            )
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_script and data:
            self.inline_script += "\n" + data[:20000]


class SafeHttpClient:
    def __init__(self, *, headers: dict[str, str], delay: float, timeout: int, max_body_bytes: int, dashboard: LiveDashboard) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT, **headers})
        self.delay = max(0.0, delay)
        self.timeout = max(3, int(timeout))
        self.max_body_bytes = max(16384, int(max_body_bytes))
        self.last_request_at = 0.0
        self.dashboard = dashboard
        self.request_count = 0
        self.pause_until = 0.0

    def get(self, url: str, *, allow_redirects: bool = True) -> FetchResult:
        wait_for = max(self.pause_until - now(), self.delay - (now() - self.last_request_at))
        if wait_for > 0:
            time.sleep(min(wait_for, 10))
        self.last_request_at = now()
        started = now()
        self.request_count += 1
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=allow_redirects, stream=True)
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= self.max_body_bytes:
                    break
            response.close()
            elapsed = int((now() - started) * 1000)
            text = b"".join(chunks).decode(response.encoding or "utf-8", errors="ignore")
            headers = {str(k): str(v) for k, v in response.headers.items()}
            if response.status_code in {429, 503}:
                self.pause_until = now() + min(10, self.delay + 3)
            return FetchResult(
                url=str(response.url),
                status_code=int(response.status_code),
                headers=headers,
                text=text,
                elapsed_ms=elapsed,
                content_type=headers.get("Content-Type", ""),
            )
        except Exception as exc:
            elapsed = int((now() - started) * 1000)
            return FetchResult(url=url, status_code=0, headers={}, text="", elapsed_ms=elapsed, content_type="", error=str(exc)[:500])


class SafeWebScanner:
    def __init__(
        self,
        target: str,
        *,
        scan_mode: str = "passive",
        include_subdomains: bool = False,
        headers: dict[str, str] | None = None,
        max_pages: int = 60,
        max_depth: int = 2,
        max_params: int = 120,
        request_timeout: int = 8,
        delay: float = 0.35,
        max_body_bytes: int = 1024 * 1024,
        live_dashboard: bool = True,
    ) -> None:
        self.target = normalize_target(target)
        self.parts = target_components(self.target)
        self.host = self.parts["domain"]
        self.scan_mode = scan_mode if scan_mode in {"passive", "safe-active", "lab"} else "passive"
        self.include_subdomains = include_subdomains
        self.max_pages = max(1, int(max_pages))
        self.max_depth = max(0, int(max_depth))
        self.max_params = max(1, int(max_params))
        self.dashboard = LiveDashboard(self.target, max_turns=max_pages + max_params, enabled=True, live_stream=live_dashboard)
        self.client = SafeHttpClient(headers=headers or {}, delay=delay, timeout=request_timeout, max_body_bytes=max_body_bytes, dashboard=self.dashboard)
        self.urls: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[FormTarget] = []
        self.params: dict[tuple[str, str], ParamTarget] = {}
        self.findings: list[Finding] = []
        self.events: list[dict[str, Any]] = []

    def _event(self, level: str, message: str, *, url: str | None = None, param: str | None = None, probe: str = "—", evidence: str = "", progress: int = 0) -> None:
        target_url = url or self.target
        parts = target_components(target_url)
        self.dashboard.update(
            phase="Real Safe Web Scan",
            phase_progress=progress,
            requests=self.client.request_count,
            findings=len(self.findings),
            endpoint=parts["endpoint"],
            domain=parts["domain"],
            request_line=parts["request_line"],
            path=parts["path"],
            parameters=param or parts["parameters"],
            probe_string=probe,
            action=message,
            hypothesis="Crawl, inventory, and safe canary validation",
            evidence=evidence,
            safety_status="Authorized scope only • transparent UA • no stealth routing • no production data modification",
        )
        self.dashboard.event(level, message)
        self.events.append({"time": now(), "level": level, "message": message, "url": target_url, "parameter": param, "probe": probe, "evidence": evidence})

    def _finding(self, **kwargs: Any) -> None:
        finding = Finding(id=f"web_{len(self.findings) + 1:03d}", **kwargs)
        self.findings.append(finding)
        self.dashboard.add_finding(
            finding.title,
            finding.impact,
            finding.severity.upper(),
            url=finding.affected_url,
            parameter=finding.parameter or "—",
            test_string=finding.safe_probe or "safe-observation",
            evidence=finding.evidence,
            cvss="N/A",
            confidence=f"{finding.confidence}%",
            reproduction="\n".join(finding.reproduction_steps),
            confirmation="confirmed" if finding.status.lower() == "confirmed" else "review_lead",
        )

    def in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if is_asset(url):
            return False
        return same_scope(url, self.host, self.include_subdomains)

    def add_params_from_url(self, url: str, source: str) -> None:
        query = parse_qs(urlparse(url).query, keep_blank_values=True)
        for name, values in query.items():
            key = (url, name)
            if key not in self.params and len(self.params) < self.max_params:
                self.params[key] = ParamTarget(url=url, parameter=name, value=values[0] if values else "", source=source, kind=parameter_kind(name))

    def check_headers(self, result: FetchResult) -> None:
        if result.error:
            return
        missing = [header for header in SECURITY_HEADERS if header not in result.headers]
        for header in missing:
            severity = "MEDIUM" if header in {"Content-Security-Policy", "Strict-Transport-Security"} else "LOW"
            self._finding(
                title=f"Missing {header} Header",
                status="Confirmed",
                severity=severity,
                confidence=98,
                category="Security Headers",
                affected_url=result.url,
                parameter=None,
                evidence=f"{header} header was not present in the HTTP response.",
                impact=f"Missing {header} reduces browser or transport hardening.",
                recommendation=f"Add a properly configured {header} header.",
                response_status=result.status_code,
                response_time_ms=result.elapsed_ms,
                reproduction_steps=[f"Send a GET request to {result.url}.", f"Review response headers and confirm {header} is absent."],
            )
        csp = result.headers.get("Content-Security-Policy", "")
        cors = result.headers.get("Access-Control-Allow-Origin", "")
        creds = result.headers.get("Access-Control-Allow-Credentials", "")
        if cors == "*" and creds.lower() == "true":
            self._finding(
                title="Credentialed CORS With Wildcard Origin",
                status="Confirmed",
                severity="HIGH",
                confidence=98,
                category="CORS",
                affected_url=result.url,
                parameter=None,
                evidence="Access-Control-Allow-Origin is * and Access-Control-Allow-Credentials is true.",
                impact="Credentialed wildcard CORS can expose authenticated responses to untrusted origins.",
                recommendation="Use explicit trusted origins when credentials are enabled.",
                response_status=result.status_code,
                response_time_ms=result.elapsed_ms,
                reproduction_steps=[f"Send a GET request to {result.url}.", "Review the Access-Control-Allow-Origin and Access-Control-Allow-Credentials headers."],
            )
        if csp and "unsafe-inline" in csp.lower():
            self._finding(
                title="CSP Allows Unsafe Inline Script",
                status="Confirmed",
                severity="LOW",
                confidence=90,
                category="CSP",
                affected_url=result.url,
                parameter=None,
                evidence=clean(csp, 300),
                impact="A permissive CSP can reduce browser-side protection value.",
                recommendation="Prefer nonces or hashes instead of unsafe-inline where feasible.",
                response_status=result.status_code,
                response_time_ms=result.elapsed_ms,
                reproduction_steps=[f"Send a GET request to {result.url}.", "Review the Content-Security-Policy header."],
            )

    def check_cookies(self, result: FetchResult) -> None:
        raw = result.headers.get("Set-Cookie", "")
        if not raw:
            return
        for cookie in re.split(r",\s*(?=[^;,]+=)", raw):
            name = cookie.split("=", 1)[0].strip()[:80]
            lowered = cookie.lower()
            missing = []
            if urlparse(result.url).scheme == "https" and "secure" not in lowered:
                missing.append("Secure")
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")
            if missing:
                self._finding(
                    title=f"Cookie Missing Hardening Flags: {name}",
                    status="Confirmed",
                    severity="LOW",
                    confidence=95,
                    category="Cookies",
                    affected_url=result.url,
                    parameter=None,
                    evidence=f"Cookie {name} is missing: {', '.join(missing)}. Value masked.",
                    impact="Missing cookie flags can weaken browser-side session protection.",
                    recommendation="Set Secure, HttpOnly, and SameSite where applicable.",
                    response_status=result.status_code,
                    response_time_ms=result.elapsed_ms,
                    reproduction_steps=[f"Send a GET request to {result.url}.", "Review Set-Cookie response headers."],
                )

    def crawl(self) -> None:
        queue: deque[tuple[str, int]] = deque([(self.target, 0)])
        seen: set[str] = set()
        while queue and len(self.urls) < self.max_pages:
            url, depth = queue.popleft()
            url = canonicalize_url(url)
            if url in seen or depth > self.max_depth or not self.in_scope(url):
                continue
            seen.add(url)
            if is_sensitive_path(url) and depth > 0:
                self._event("INFO", "Sensitive workflow path inventoried but not crawled deeply", url=url, progress=int(len(self.urls) * 100 / self.max_pages))
                self.urls.add(url)
                self.add_params_from_url(url, "sensitive-link")
                continue
            self._event("INFO", f"Crawling page depth={depth}", url=url, progress=int(len(self.urls) * 100 / self.max_pages))
            result = self.client.get(url)
            if result.error:
                self._event("WARNING", "Request failed; moving on", url=url, evidence=result.error, progress=int(len(self.urls) * 100 / self.max_pages))
                continue
            self.urls.add(result.url)
            self.add_params_from_url(result.url, "url-query")
            if len(self.urls) == 1:
                self.check_headers(result)
                self.check_cookies(result)
            if result.status_code >= 500:
                self._finding(
                    title="Server Error Observed During Safe Crawl",
                    status="Confirmed",
                    severity="LOW",
                    confidence=85,
                    category="Error Behavior",
                    affected_url=result.url,
                    parameter=None,
                    evidence=f"Safe GET request returned HTTP {result.status_code}.",
                    impact="Unexpected server errors can expose instability or error-handling gaps.",
                    recommendation="Review server logs and error handling for the affected route.",
                    response_status=result.status_code,
                    response_time_ms=result.elapsed_ms,
                    reproduction_steps=[f"Send a GET request to {result.url}."],
                )
            if "html" not in result.content_type.lower() and "<html" not in result.text[:800].lower():
                continue
            parser = LinkFormParser(result.url)
            try:
                parser.feed(result.text)
            except Exception:
                pass
            self.forms.extend(parser.forms)
            self.scripts.update({script for script in parser.scripts if self.in_scope(script)})
            for form in parser.forms:
                if form.method == "GET" and self.in_scope(form.action_url) and not is_sensitive_path(form.action_url):
                    parsed = urlparse(form.action_url)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    for name, value in form.parameters.items():
                        query.setdefault(name, [value])
                    form_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(query, doseq=True), ""))
                    for name, value in form.parameters.items():
                        key = (form_url, name)
                        if key not in self.params and len(self.params) < self.max_params:
                            self.params[key] = ParamTarget(url=form_url, parameter=name, value=value, source="GET-form", kind=parameter_kind(name))
            for link in parser.links:
                if self.in_scope(link):
                    self.add_params_from_url(link, "link-query")
                    if canonicalize_url(link) not in seen and len(self.urls) + len(queue) < self.max_pages * 2:
                        queue.append((link, depth + 1))
            for endpoint in self.extract_js_routes(parser.inline_script, result.url):
                if self.in_scope(endpoint):
                    self.add_params_from_url(endpoint, "inline-js")
                    if canonicalize_url(endpoint) not in seen:
                        queue.append((endpoint, depth + 1))
        self._event("SUCCESS", f"Crawl completed: urls={len(self.urls)} params={len(self.params)} forms={len(self.forms)} scripts={len(self.scripts)}", url=self.target, progress=100)

    def extract_js_routes(self, script_text: str, base_url: str) -> set[str]:
        routes: set[str] = set()
        for pattern in [r"['\"](/api/[^'\"\s<>]+)['\"]", r"['\"](/[A-Za-z0-9_./-]+\?[^'\"\s<>]+)['\"]"]:
            for match in re.finditer(pattern, script_text or ""):
                routes.add(urljoin(base_url, match.group(1)))
        return routes

    def analyze_scripts(self) -> None:
        for index, script_url in enumerate(list(self.scripts)[:20], 1):
            self._event("INFO", f"Reviewing JavaScript {index}/{min(len(self.scripts), 20)}", url=script_url, progress=min(100, int(index * 100 / max(1, min(len(self.scripts), 20)))))
            result = self.client.get(script_url)
            if result.error or result.status_code != 200:
                continue
            for route in self.extract_js_routes(result.text, result.url):
                if self.in_scope(route):
                    self.urls.add(route)
                    self.add_params_from_url(route, "external-js")
            if re.search(r"(?i)(api[_-]?key|access[_-]?token|secret)\s*[:=]\s*['\"][^'\"]{8,}", result.text):
                self._finding(
                    title="Possible Client-Side Secret Pattern",
                    status="Manual Review Lead",
                    severity="MEDIUM",
                    confidence=70,
                    category="JavaScript",
                    affected_url=result.url,
                    parameter=None,
                    evidence="A key/token/secret-like variable name was observed in JavaScript. Value is intentionally not displayed.",
                    impact="Client-side secrets can expose sensitive integration details if real.",
                    recommendation="Review the JavaScript source and remove real secrets from client-delivered code.",
                    response_status=result.status_code,
                    response_time_ms=result.elapsed_ms,
                    reproduction_steps=[f"Open the JavaScript file: {result.url}", "Search for key/token/secret-like variable names."],
                )
            if "sourceMappingURL=" in result.text:
                source_map = script_url + ".map" if script_url.endswith(".js") else ""
                if source_map and self.in_scope(source_map):
                    sm = self.client.get(source_map)
                    if sm.status_code == 200 and "sources" in sm.text[:5000]:
                        self._finding(
                            title="Public Source Map Accessible",
                            status="Confirmed",
                            severity="MEDIUM",
                            confidence=90,
                            category="JavaScript",
                            affected_url=source_map,
                            parameter=None,
                            evidence="Source map returned HTTP 200 and contains source references.",
                            impact="Public source maps can reveal application structure and source code context.",
                            recommendation="Do not publish production source maps unless intentionally public.",
                            response_status=sm.status_code,
                            response_time_ms=sm.elapsed_ms,
                            reproduction_steps=[f"Open {source_map} and review the source map metadata."],
                        )

    def inventory_risk_leads(self) -> None:
        for param in list(self.params.values())[: self.max_params]:
            if param.kind == "id-like":
                self._finding(
                    title="ID-Like Parameter Requires Authorization Review",
                    status="Manual Review Lead",
                    severity="INFO",
                    confidence=75,
                    category="IDOR Review",
                    affected_url=param.url,
                    parameter=param.parameter,
                    evidence=f"Parameter `{param.parameter}` is ID-like. No ID mutation was performed.",
                    impact="ID-like parameters commonly require object-level authorization validation.",
                    recommendation="Manually validate object authorization with approved test accounts only.",
                    safe_probe="classification-only",
                    reproduction_steps=[f"Review parameter `{param.parameter}` at {param.url}.", "Use authorized test accounts to validate object-level access controls."],
                )
            elif param.kind == "url-like":
                self._finding(
                    title="URL-Like Parameter Requires Server-Side Fetch Review",
                    status="Manual Review Lead",
                    severity="INFO",
                    confidence=70,
                    category="SSRF Review",
                    affected_url=param.url,
                    parameter=param.parameter,
                    evidence=f"Parameter `{param.parameter}` appears URL-like. No internal network target was requested.",
                    impact="URL-like parameters can require review for server-side fetch behavior.",
                    recommendation="Validate with an approved collaborator endpoint in an authorized environment.",
                    safe_probe="classification-only",
                    reproduction_steps=[f"Review parameter `{param.parameter}` at {param.url}."],
                )
            elif param.kind == "file-like":
                self._finding(
                    title="File/Path-Like Parameter Requires Path Handling Review",
                    status="Manual Review Lead",
                    severity="INFO",
                    confidence=70,
                    category="Path Handling Review",
                    affected_url=param.url,
                    parameter=param.parameter,
                    evidence=f"Parameter `{param.parameter}` appears file/path-like. No traversal string was sent.",
                    impact="File/path parameters can require validation for path resolution and allowlisting.",
                    recommendation="Validate path allowlisting in a staging or explicitly approved environment.",
                    safe_probe="classification-only",
                    reproduction_steps=[f"Review parameter `{param.parameter}` at {param.url}."],
                )

    def test_parameter_canaries(self) -> None:
        if self.scan_mode not in {"safe-active", "lab"}:
            self._event("INFO", "Passive mode: active canary parameter checks skipped", url=self.target, progress=100)
            return
        targets = list(self.params.values())[: self.max_params]
        for index, param in enumerate(targets, 1):
            progress = int(index * 100 / max(1, len(targets)))
            if is_sensitive_path(param.url):
                self._event("INFO", "Parameter on sensitive workflow skipped", url=param.url, param=param.parameter, probe="skip-sensitive", progress=progress)
                continue
            probe = safe_canary()
            test_url = replace_param(param.url, param.parameter, probe)
            self._event("INFO", f"Testing parameter {param.parameter} with safe canary", url=test_url, param=param.parameter, probe=probe, progress=progress)
            result = self.client.get(test_url, allow_redirects=False)
            if result.error:
                self._event("WARNING", "Safe parameter request failed", url=test_url, param=param.parameter, probe=probe, evidence=result.error, progress=progress)
                continue
            if probe in result.text:
                self._finding(
                    title="Reflected Input Observation",
                    status="Confirmed",
                    severity="LOW",
                    confidence=95,
                    category="Reflection",
                    affected_url=test_url,
                    parameter=param.parameter,
                    evidence=f"Exact harmless canary `{probe}` appeared in the response body.",
                    impact="Confirmed reflection is not automatically XSS, but it identifies an output context that requires encoding review.",
                    recommendation="Review output encoding for the reflected parameter and validate context manually.",
                    response_status=result.status_code,
                    response_time_ms=result.elapsed_ms,
                    safe_probe=probe,
                    reproduction_steps=[f"Open {param.url}.", f"Set `{param.parameter}` to `{probe}`.", "Confirm the exact canary appears in the response body."],
                )
            if result.status_code >= 500:
                self._finding(
                    title="Parameter Input Caused Server Error",
                    status="Confirmed",
                    severity="MEDIUM",
                    confidence=85,
                    category="Input Handling",
                    affected_url=test_url,
                    parameter=param.parameter,
                    evidence=f"Harmless canary request returned HTTP {result.status_code}.",
                    impact="Unexpected server errors during harmless input handling can indicate fragile validation or exception handling.",
                    recommendation="Review server-side validation and exception handling for the affected parameter.",
                    response_status=result.status_code,
                    response_time_ms=result.elapsed_ms,
                    safe_probe=probe,
                    reproduction_steps=[f"Set `{param.parameter}` to `{probe}` on {param.url}."],
                )
            if param.kind == "redirect-like" and result.status_code in {301, 302, 303, 307, 308}:
                location = result.headers.get("Location", "")
                absolute = urljoin(result.url, location)
                status = "Confirmed" if same_scope(absolute, self.host, self.include_subdomains) else "Manual Review Lead"
                severity = "INFO" if status == "Confirmed" else "MEDIUM"
                self._finding(
                    title="Redirect Parameter Behavior Observed",
                    status=status,
                    severity=severity,
                    confidence=80,
                    category="Redirect Review",
                    affected_url=test_url,
                    parameter=param.parameter,
                    evidence=f"HTTP {result.status_code} Location: {clean(location, 180)}",
                    impact="Redirect parameters require strict destination validation. This check did not use an external destination.",
                    recommendation="Ensure redirect destinations are allowlisted and normalized safely.",
                    response_status=result.status_code,
                    response_time_ms=result.elapsed_ms,
                    safe_probe=probe,
                    reproduction_steps=[f"Set `{param.parameter}` to a same-site safe canary path on {param.url}."],
                )

    def write_reports(self) -> dict[str, str]:
        out = cai_output_dir(self.target)
        payload = {
            "version": VERSION,
            "target": self.target,
            "scan_mode": self.scan_mode,
            "generated_at": now(),
            "urls": sorted(self.urls),
            "forms": [asdict(item) for item in self.forms],
            "parameters": [asdict(item) for item in self.params.values()],
            "findings": [asdict(item) for item in self.findings],
            "events": self.events[-500:],
            "summary": {
                "url_count": len(self.urls),
                "form_count": len(self.forms),
                "parameter_count": len(self.params),
                "finding_count": len(self.findings),
                "request_count": self.client.request_count,
            },
            "safety": {
                "same_scope_only": True,
                "transparent_user_agent": DEFAULT_USER_AGENT,
                "stealth_routing": False,
                "ip_rotation": False,
                "target_data_modification": False,
                "dangerous_payloads": False,
            },
        }
        json_path = out / "safe-web-scan.json"
        md_path = out / "safe-web-scan.md"
        params_path = out / "parameter-inventory.json"
        write_json(json_path, payload)
        write_json(params_path, payload["parameters"])
        lines = [
            "# VulnScope Real Safe Web Scan",
            "",
            f"Target: `{self.target}`",
            f"Mode: `{self.scan_mode}`",
            f"URLs: `{len(self.urls)}`",
            f"Forms: `{len(self.forms)}`",
            f"Parameters: `{len(self.params)}`",
            f"Findings / leads: `{len(self.findings)}`",
            f"Requests: `{self.client.request_count}`",
            "",
            "## Parameter Inventory",
            "",
        ]
        for item in list(self.params.values())[:200]:
            lines.append(f"- `{item.parameter}` kind=`{item.kind}` source=`{item.source}` url=`{item.url}`")
        lines += ["", "## Findings", ""]
        if not self.findings:
            lines.append("No confirmed findings or review leads were generated by the safe web scan.")
        for finding in self.findings:
            lines.extend([
                f"### {finding.id} — {finding.title}",
                f"- Status: `{finding.status}`",
                f"- Severity: `{finding.severity}`",
                f"- Confidence: `{finding.confidence}%`",
                f"- Category: `{finding.category}`",
                f"- URL: `{finding.affected_url}`",
                f"- Parameter: `{finding.parameter or 'N/A'}`",
                f"- Evidence: {finding.evidence}",
                f"- Impact: {finding.impact}",
                f"- Recommendation: {finding.recommendation}",
                "",
            ])
        write_markdown(md_path, lines)
        return {"safe_web_scan_json": str(json_path), "safe_web_scan_md": str(md_path), "parameter_inventory_json": str(params_path)}

    def run(self) -> dict[str, Any]:
        self.dashboard.start()
        try:
            self._event("INFO", "Starting real safe web scan", url=self.target, progress=0)
            root = self.client.get(self.target)
            if root.error:
                self._event("WARNING", "Root request failed; crawler will still attempt target URL", url=self.target, evidence=root.error, progress=1)
            else:
                self.urls.add(root.url)
                self.add_params_from_url(root.url, "root-query")
                self.check_headers(root)
                self.check_cookies(root)
            self.crawl()
            self.analyze_scripts()
            self.inventory_risk_leads()
            self.test_parameter_canaries()
            reports = self.write_reports()
            self.dashboard.report_paths.update(reports)
            self._event("SUCCESS", f"Safe web scan completed: urls={len(self.urls)} params={len(self.params)} findings={len(self.findings)}", url=self.target, progress=100)
            return {
                "status": "completed",
                "target": self.target,
                "summary": {"urls": len(self.urls), "forms": len(self.forms), "parameters": len(self.params), "findings": len(self.findings), "requests": self.client.request_count},
                "reports": reports,
            }
        finally:
            self.dashboard.stop(final=False)


def parse_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values or []:
        if ":" not in value:
            continue
        name, body = value.split(":", 1)
        if name.strip() and body.strip():
            headers[name.strip()] = body.strip()
    return headers


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope real safe web crawler and parameter scanner")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scan-mode", default="passive", choices=["passive", "safe-active", "lab"])
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--max-pages", type=int, default=60)
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-params", type=int, default=120)
    parser.add_argument("--request-timeout", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.35)
    parser.add_argument("--no-live-dashboard", action="store_true")
    args = parser.parse_args()
    scanner = SafeWebScanner(
        args.target,
        scan_mode=args.scan_mode,
        include_subdomains=args.include_subdomains,
        headers=parse_headers(args.header),
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        max_params=args.max_params,
        request_timeout=args.request_timeout,
        delay=args.delay,
        live_dashboard=not args.no_live_dashboard,
    )
    payload = scanner.run()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
