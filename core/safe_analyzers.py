#!/usr/bin/env python3
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from core.http_client_v2 import ResponseRecord, SafeHttpClientV2
from core.parameter_inventory import add_params_from_url
from core.scan_state import ScanState
from core.test_engine import TestEngine

SECURITY_HEADERS = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]


@dataclass
class AnalyzerSummary:
    availability_checked: bool = False
    headers_checked: bool = False
    cookies_checked: bool = False
    metadata_checked: bool = False
    findings_added: int = 0
    analyzer_errors: int = 0


class PassiveAnalyzers:
    def __init__(self, *, state: ScanState, client: SafeHttpClientV2, tester: TestEngine, dashboard: object | None = None) -> None:
        self.state = state
        self.client = client
        self.tester = tester
        self.dashboard = dashboard
        self.summary = AnalyzerSummary()

    def _dash(self, agent: str, tool: str, message: str, *, response: ResponseRecord | None = None, progress: int = 0, status: str = "running") -> None:
        url = response.url if response else self.state.target
        parsed = urlparse(url)
        path = parsed.path or "/"
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(current_agent=agent, current_tool=tool, tool_status=status, decision=status, phase="Passive Analysis", phase_progress=progress, endpoint=url, request_line="GET " + path + (("?" + parsed.query) if parsed.query else ""), path=path, parameters=parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope.", response_code=str(response.status_code) if response else "—", response_time_ms=str(response.elapsed_ms) if response else "—", evidence=message, action=message)
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            level = "ERROR" if status == "failed" else "SUCCESS" if status == "completed" else "INFO"
            self.dashboard.event(level, f"{tool}: {message}")

    def _safe_step(self, name: str, fn: object) -> None:
        try:
            fn()
        except Exception as exc:
            self.summary.analyzer_errors += 1
            try:
                self.state.add_event("WARNING", "passive analyzer step failed", analyzer=name, error=str(exc)[:500])
            except Exception:
                pass
            self._dash("ReconAgent", name, f"Analyzer step failed but scan will continue: {str(exc)[:180]}", progress=20, status="failed")

    def run_all(self, root_response: ResponseRecord | None = None) -> AnalyzerSummary:
        before = len(self.state.findings)
        root = root_response if root_response and root_response.ok else self.client.get(self.state.target, purpose="passive-root")
        self._safe_step("availability_checker", lambda: self.check_availability(root))
        if root.ok:
            self._safe_step("header_analyzer", lambda: self.check_headers(root))
            self._safe_step("cookie_analyzer", lambda: self.check_cookies(root))
        else:
            self._dash("HeaderAnalysisAgent", "header_analyzer", "Skipped because target root response was not OK", response=root, progress=12, status="skipped")
            self._dash("CookieAnalysisAgent", "cookie_analyzer", "Skipped because target root response was not OK", response=root, progress=15, status="skipped")
        self._safe_step("metadata_checker", self.check_metadata_files)
        self.summary.findings_added = len(self.state.findings) - before
        self.state.save()
        return self.summary

    def check_availability(self, response: ResponseRecord) -> None:
        self.summary.availability_checked = True
        self._dash("ReconAgent", "availability_checker", f"HTTP {response.status_code}" if response.ok else f"Request failed: {response.error}", response=response, progress=8, status="completed" if response.received else "failed")
        if not response.ok:
            self.tester._finding(title="Target Availability Check Failed", status="Informational", severity="INFO", confidence=70, category="Availability", url=response.url, parameter=None, evidence=response.error or "No HTTP response was captured.", impact="The scan could not confirm reachability from this environment.", recommendation="Check connectivity, DNS, or target availability, then resume the scan.", response=response, probe="availability-check")

    def check_headers(self, response: ResponseRecord) -> None:
        self.summary.headers_checked = True
        self._dash("HeaderAnalysisAgent", "header_analyzer", "Checking response headers", response=response, progress=12, status="running")
        missing_count = 0
        for header in SECURITY_HEADERS:
            if header not in response.headers:
                missing_count += 1
                self.tester._finding(title=f"Missing {header} Header", status="Informational", severity="INFO", confidence=95, category="Security Headers", url=response.url, parameter=None, evidence=f"The HTTP response did not include the `{header}` header.", impact=f"Missing {header} is a hardening observation. It is not proof of an exploitable vulnerability by itself.", recommendation=f"Configure `{header}` where appropriate for this application.", response=response, probe="passive-header-check", steps=[f"Send a GET request to {response.url}.", f"Review response headers and confirm `{header}` is absent."])
        csp = response.headers.get("Content-Security-Policy", "")
        if csp and "unsafe-inline" in csp.lower():
            self.tester._finding(title="CSP Contains unsafe-inline", status="Informational", severity="INFO", confidence=90, category="CSP", url=response.url, parameter=None, evidence=csp[:500], impact="A permissive CSP is a browser hardening observation, not a confirmed exploit.", recommendation="Prefer nonces or hashes where feasible instead of broad inline script allowances.", response=response, probe="passive-csp-check")
        self._dash("HeaderAnalysisAgent", "header_analyzer", f"Header review completed; missing hardening headers={missing_count}", response=response, progress=13, status="completed")

    def check_cookies(self, response: ResponseRecord) -> None:
        self.summary.cookies_checked = True
        self._dash("CookieAnalysisAgent", "cookie_analyzer", "Checking Set-Cookie flags", response=response, progress=15, status="running")
        raw = response.headers.get("Set-Cookie", "")
        cookie_count = 0
        if raw:
            for cookie in re.split(r",\s*(?=[^;,]+=)", raw):
                cookie_count += 1
                name = cookie.split("=", 1)[0].strip()[:80]
                lower = cookie.lower()
                missing = []
                if urlparse(response.url).scheme == "https" and "secure" not in lower:
                    missing.append("Secure")
                if "httponly" not in lower:
                    missing.append("HttpOnly")
                if "samesite" not in lower:
                    missing.append("SameSite")
                if missing:
                    self.tester._finding(title=f"Cookie Missing Hardening Flags: {name}", status="Informational", severity="INFO", confidence=90, category="Cookies", url=response.url, parameter=None, evidence=f"Cookie `{name}` is missing: {', '.join(missing)}. Cookie value was masked.", impact="Missing cookie flags are a hardening observation unless tied to an exploitable workflow.", recommendation="Set Secure, HttpOnly, and SameSite attributes where applicable.", response=response, probe="passive-cookie-check")
        self._dash("CookieAnalysisAgent", "cookie_analyzer", f"Cookie review completed; set-cookie count={cookie_count}", response=response, progress=16, status="completed")

    def check_metadata_files(self) -> None:
        self.summary.metadata_checked = True
        base = f"{urlparse(self.state.target).scheme}://{urlparse(self.state.target).netloc}"
        checked = 0
        for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]:
            response = self.client.get(urljoin(base, path), purpose="metadata-check")
            checked += 1
            self._dash("ReconAgent", "metadata_checker", f"Checked {path}: HTTP {response.status_code}", response=response, progress=20, status="running")
            if response.status_code != 200:
                continue
            if path.endswith("robots.txt"):
                disallows = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", response.text)
                for item in disallows[:120]:
                    discovered = urljoin(base, item)
                    self.state.add_url(discovered, depth=1, source="robots")
                    add_params_from_url(self.state, discovered, "robots")
                if disallows:
                    self.tester._finding(title="robots.txt Exposes Crawl Directives", status="Informational", severity="INFO", confidence=90, category="Metadata", url=response.url, parameter=None, evidence=f"robots.txt contains {len(disallows)} Disallow entries. Example: {', '.join(disallows[:5])}", impact="robots.txt can reveal route names and application structure. It is not access control.", recommendation="Do not rely on robots.txt to protect sensitive paths; enforce server-side authorization.", response=response, probe="passive-robots-check")
            if path.endswith("sitemap.xml"):
                urls = re.findall(r"<loc>\s*([^<]+)\s*</loc>", response.text, re.I)
                for discovered in urls[:500]:
                    self.state.add_url(discovered, depth=1, source="sitemap")
                    add_params_from_url(self.state, discovered, "sitemap")
        self._dash("ReconAgent", "metadata_checker", f"Metadata review completed; documents checked={checked}", progress=21, status="completed")
