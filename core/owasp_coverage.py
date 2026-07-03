#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cai_error_handler import write_json, write_markdown
from core.scan_state import ScanState


WEB_TOP_10_2025 = [
    "A01 Broken Access Control",
    "A02 Security Misconfiguration",
    "A03 Software Supply Chain Failures",
    "A04 Cryptographic Failures",
    "A05 Injection",
    "A06 Insecure Design",
    "A07 Authentication Failures",
    "A08 Software and Data Integrity Failures",
    "A09 Logging and Alerting Failures",
    "A10 Server-Side Request Forgery",
]

API_TOP_10_2023 = [
    "API1 Broken Object Level Authorization",
    "API2 Broken Authentication",
    "API3 Broken Object Property Level Authorization",
    "API4 Unrestricted Resource Consumption",
    "API5 Broken Function Level Authorization",
    "API6 Unrestricted Access to Sensitive Business Flows",
    "API7 Server Side Request Forgery",
    "API8 Security Misconfiguration",
    "API9 Improper Inventory Management",
    "API10 Unsafe Consumption of APIs",
]


class OWASPCoverageReporter:
    """Safe OWASP coverage reporter.

    This module does not add exploit payloads. It maps discovered assets,
    parameters, passive findings, and safe test outcomes to OWASP review areas
    so the final report shows what was covered and what still needs authorized
    manual/staging validation.
    """

    def __init__(self, state: ScanState) -> None:
        self.state = state
        self.out = state.out_dir

    def _url_flags(self, url: str) -> list[str]:
        path = (urlparse(url).path or "/").lower()
        query = (urlparse(url).query or "").lower()
        flags: list[str] = []
        if re.search(r"/api/|graphql|/json|/rest|/v\d+", path):
            flags.append("api-surface")
        if re.search(r"admin|manage|dashboard|panel|staff", path):
            flags.append("privileged-function")
        if re.search(r"login|signin|auth|account|profile|user", path):
            flags.append("auth-or-identity")
        if re.search(r"upload|file|download|document|media", path + "?" + query):
            flags.append("file-or-resource")
        if re.search(r"redirect|return|next|url|callback|continue|dest", query):
            flags.append("redirect-or-ssrf-like")
        if re.search(r"id=|user_id=|account|order|invoice|profile", query):
            flags.append("object-reference")
        return sorted(set(flags))

    def _param_owasp(self, kind: str) -> list[str]:
        mapping = {
            "object-like": ["A01 Broken Access Control", "API1 Broken Object Level Authorization", "API3 Broken Object Property Level Authorization"],
            "resource-like": ["A01 Broken Access Control", "A05 Injection", "API3 Broken Object Property Level Authorization"],
            "route-like": ["A02 Security Misconfiguration", "A10 Server-Side Request Forgery", "API7 Server Side Request Forgery"],
            "reference-like": ["A10 Server-Side Request Forgery", "API7 Server Side Request Forgery", "API10 Unsafe Consumption of APIs"],
            "search-like": ["A05 Injection", "A03 Software Supply Chain Failures"],
            "state-like": ["A06 Insecure Design", "API6 Unrestricted Access to Sensitive Business Flows"],
            "generic": ["A05 Injection", "A06 Insecure Design"],
        }
        return mapping.get(kind, ["A06 Insecure Design"])

    def coverage(self) -> dict[str, Any]:
        urls = list(self.state.urls.values())
        params = list(self.state.params.values())
        tests = list(self.state.tests.values())
        findings = list(self.state.findings)
        category_counts = {name: 0 for name in WEB_TOP_10_2025 + API_TOP_10_2023}
        param_reviews: list[dict[str, Any]] = []
        asset_reviews: list[dict[str, Any]] = []
        for param in sorted(params, key=lambda p: p.risk_score, reverse=True):
            mapped = self._param_owasp(param.kind)
            for item in mapped:
                category_counts[item] = category_counts.get(item, 0) + 1
            param_reviews.append({
                "url": param.url,
                "parameter": param.name,
                "kind": param.kind,
                "risk_score": param.risk_score,
                "status": param.status,
                "tested": list(param.tested),
                "owasp_mapping": mapped,
                "safe_gap": "requires authorized manual/staging validation" if param.kind in {"object-like", "resource-like"} else "covered by safe review ladder",
            })
        for url in urls:
            flags = self._url_flags(url.url)
            mapped: list[str] = []
            if "api-surface" in flags:
                mapped.extend(["API9 Improper Inventory Management", "API8 Security Misconfiguration"])
            if "privileged-function" in flags:
                mapped.extend(["A01 Broken Access Control", "API5 Broken Function Level Authorization"])
            if "auth-or-identity" in flags:
                mapped.extend(["A07 Authentication Failures", "API2 Broken Authentication"])
            if "redirect-or-ssrf-like" in flags:
                mapped.extend(["A10 Server-Side Request Forgery", "API7 Server Side Request Forgery"])
            if "object-reference" in flags:
                mapped.extend(["A01 Broken Access Control", "API1 Broken Object Level Authorization"])
            for item in set(mapped):
                category_counts[item] = category_counts.get(item, 0) + 1
            if flags:
                asset_reviews.append({"url": url.url, "depth": url.depth, "status": url.status, "flags": flags, "owasp_mapping": sorted(set(mapped))})
        return {
            "target": self.state.target,
            "coverage": self.state.coverage(),
            "web_top_10_reference": WEB_TOP_10_2025,
            "api_top_10_reference": API_TOP_10_2023,
            "category_counts": category_counts,
            "asset_reviews": asset_reviews[:250],
            "parameter_reviews": param_reviews[:500],
            "tests": [asdict(item) for item in tests],
            "findings_total": len(findings),
            "safe_note": "This report maps safe evidence and review leads to OWASP categories. It does not claim exploitability unless the final findings dashboard marks an item confirmed.",
        }

    def write_json(self) -> Path:
        path = self.out / "owasp-coverage-report.json"
        write_json(path, self.coverage())
        return path

    def write_markdown(self) -> Path:
        data = self.coverage()
        path = self.out / "owasp-coverage-report.md"
        lines = [
            "# VulnScope Safe OWASP Coverage Report",
            "",
            f"Target: `{data['target']}`",
            "",
            "This is a safe coverage report. It maps discovered assets, parameters, tests, and findings to OWASP review areas without using destructive payloads or exploit execution.",
            "",
            "## Coverage",
            "",
        ]
        cov = data["coverage"]
        lines += [
            f"- URLs: `{cov['urls_done']}/{cov['urls_total']}`",
            f"- Parameters: `{cov['params_done']}/{cov['params_total']}`",
            f"- Tests: `{cov['tests_done']}/{cov['tests_total']}`",
            f"- Findings/review leads: `{cov['findings']}`",
            "",
            "## OWASP Web Top 10 2025 Review Areas",
            "",
        ]
        for item in WEB_TOP_10_2025:
            lines.append(f"- `{item}` mapped evidence/review count: `{data['category_counts'].get(item, 0)}`")
        lines += ["", "## OWASP API Security Top 10 2023 Review Areas", ""]
        for item in API_TOP_10_2023:
            lines.append(f"- `{item}` mapped evidence/review count: `{data['category_counts'].get(item, 0)}`")
        lines += ["", "## High-Value Parameter Review Queue", ""]
        for item in data["parameter_reviews"][:80]:
            lines.append(f"- `{item['parameter']}` kind=`{item['kind']}` risk=`{item['risk_score']}` status=`{item['status']}` tested=`{','.join(item['tested']) or 'none'}` url=`{item['url']}` maps=`{'; '.join(item['owasp_mapping'])}`")
        lines += ["", "## High-Value Asset Review Queue", ""]
        for item in data["asset_reviews"][:80]:
            lines.append(f"- `{item['url']}` flags=`{','.join(item['flags'])}` maps=`{'; '.join(item['owasp_mapping'])}`")
        write_markdown(path, lines)
        return path

    def write_all(self) -> dict[str, str]:
        return {
            "owasp_coverage_json": str(self.write_json()),
            "owasp_coverage_md": str(self.write_markdown()),
        }
