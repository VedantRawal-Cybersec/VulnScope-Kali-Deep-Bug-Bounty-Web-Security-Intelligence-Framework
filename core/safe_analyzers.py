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


class PassiveAnalyzers:
    def __init__(self, *, state: ScanState, client: SafeHttpClientV2, tester: TestEngine, dashboard: object | None = None) -> None:
        self.state = state
        self.client = client
        self.tester = tester
        self.dashboard = dashboard
        self.summary = AnalyzerSummary()

    def _dash(self, agent: str, tool: str, message: str, *, response: ResponseRecord | None = None, progress: int = 0) -> None:
        url = response.url if response else self.state.target
        parsed = urlparse(url)
        path = parsed.path or "/"
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(current_agent=agent, current_tool=tool, phase="Passive Analysis", phase_progress=progress, endpoint=url, request_line="GET " + path + (("?" + parsed.query) if parsed.query else ""), path=path, parameters=parsed.query or "No safe query parameters or GET inputs were discovered in the selected scope.", response_code=str(response.status_code) if response else "—", response_time_ms=str(response.elapsed_ms) if response else "—", evidence=message, action=message)
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", f"{tool}: {message}")

    def run_all(self, root_response: ResponseRecord | None = None) -> AnalyzerSummary:
        before = len(self.state.findings)
        root = root_response if root_response and root_response.ok else self.client.get(self.state.target, purpose="passive-root")
        self.check_availability(root)
        if root.ok:
            self.check_headers(root)
            self.check_cookies(root)
        self.check_metadata_files()
        self.summary.findings_added = len(self.state.findings) - before
        self.state.save()
        return self.summary

    def check_availability(self, response: ResponseRecord) -> None:
        self.summary.availability_checked = True
        self._dash("ReconAgent", "availability_checker", f"HTTP {response.status_code}" if response.ok else f"Request failed: {response.error}", response=response, progress=8)
        if not response.ok:
            self.tester._finding(title="Target Availability Check Failed", status="Informational", severity="INFO", confidence=70, category="Availability", url=response.url, parameter=None, evidence=response.error or "No HTTP response was captured.", impact="The scan could not confirm reachability from this environment.", recommendation="Check connectivity, DNS, or target availability, then resume the scan.", response=response, probe="availability-check")

    def check_headers(self, response: ResponseRecord) -> None:
        self.summary.headers_checked = True
        self._dash("HeaderAnalysisAgent", "header_analyzer", "Checking response headers", response=response, progress=12)
        for header in SECURITY_HEADERS:
            if header not in response.headers:
                severity = "MEDIUM" if header in {"Content-Security-Policy", "Strict-Transport-Security"} else "LOW"
                self.tester._finding(title=f"Missing {header} Header", status="Confirmed", severity=severity, confidence=98, category="Security Headers", url=response.url, parameter=None, evidence=f"The HTTP response did not include the `{header}` header.", impact=f"Missing {header} reduces browser or transport hardening.", recommendation=f"Add a properly configured {header} header where applicable.", response=response, probe="passive-header-check", steps=[f"Send a GET request to {response.url}.", f"Review response headers and confirm `{header}` is absent."])
        csp = response.headers.get("Content-Security-Policy", "")
        if csp and "unsafe-inline" in csp.lower():
            self.tester._finding(title="CSP Contains unsafe-inline", status="Confirmed", severity="LOW", confidence=90, category="CSP", url=response.url, parameter=None, evidence=csp[:500], impact="A permissive CSP can reduce browser-side protection value.", recommendation="Prefer nonces or hashes where feasible instead of broad inline script allowances.", response=response, probe="passive-csp-check")

    def check_cookies(self, response: ResponseRecord) -> None:
        self.summary.cookies_checked = True
        self._dash("CookieAnalysisAgent", "cookie_analyzer", "Checking Set-Cookie flags", response=response, progress=15)
        raw = response.headers.get("Set-Cookie", "")
        if not raw:
            return
        for cookie in re.split(r",\s*(?=[^;,]+=)", raw):
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
                self.tester._finding(title=f"Cookie Missing Hardening Flags: {name}", status="Confirmed", severity="LOW", confidence=95, category="Cookies", url=response.url, parameter=None, evidence=f"Cookie `{name}` is missing: {', '.join(missing)}. Cookie value was masked.", impact="Missing cookie flags can weaken browser-side session protection.", recommendation="Set Secure, HttpOnly, and SameSite attributes where applicable.", response=response, probe="passive-cookie-check")

    def check_metadata_files(self) -> None:
        self.summary.metadata_checked = True
        base = f"{urlparse(self.state.target).scheme}://{urlparse(self.state.target).netloc}"
        for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]:
            response = self.client.get(urljoin(base, path), purpose="metadata-check")
            self._dash("ReconAgent", "metadata_checker", f"Checked {path}: HTTP {response.status_code}", response=response, progress=20)
            if response.status_code != 200:
                continue
            if path.endswith("robots.txt"):
                disallows = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", response.text)
                for item in disallows[:80]:
                    add_params_from_url(self.state, urljoin(base, item), "robots")
                if disallows:
                    self.tester._finding(title="robots.txt Exposes Crawl Directives", status="Informational", severity="INFO", confidence=90, category="Metadata", url=response.url, parameter=None, evidence=f"robots.txt contains {len(disallows)} Disallow entries. Example: {', '.join(disallows[:5])}", impact="robots.txt can reveal route names and application structure. It is not access control.", recommendation="Do not rely on robots.txt to protect sensitive paths; enforce server-side authorization.", response=response, probe="passive-robots-check")
            if path.endswith("sitemap.xml"):
                urls = re.findall(r"<loc>\s*([^<]+)\s*</loc>", response.text, re.I)
                for discovered in urls[:300]:
                    self.state.add_url(discovered, depth=1, source="sitemap")
                    add_params_from_url(self.state, discovered, "sitemap")
