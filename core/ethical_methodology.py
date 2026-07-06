#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class EthicalMethodologyLedger:
    """Evidence-based methodology ledger for authorized security assessment.

    The ledger records what was actually covered and what was intentionally gated.
    Lab-only stages are documented as review gates unless the scan mode is lab.
    """

    PHASES = [
        ("reconnaissance", "Collect reachable same-scope URLs, metadata, headers, robots, sitemap, and public assets."),
        ("surface_mapping", "Map paths, GET inputs, forms, scripts, client-side routes, and API-like endpoints."),
        ("safe_validation", "Run non-destructive baseline, canary reflection, redirect, and classification checks."),
        ("dynamic_tooling", "Run only enabled, approved, configured tools with saved stdout/stderr and parsed observations."),
        ("auth_boundary_review", "Identify object-like and role-boundary parameters that require approved test accounts."),
        ("lab_attack_chain", "In lab mode only, connect evidence into an attack-chain hypothesis for manual validation."),
        ("reporting", "Write evidence, coverage, gaps, recommendations, and reproduction notes."),
    ]

    def __init__(self, *, state: Any, mode: str, include_subdomains: bool, dynamic_ready: int = 0) -> None:
        self.state = state
        self.mode = mode
        self.include_subdomains = include_subdomains
        self.dynamic_ready = dynamic_ready
        self.host = getattr(state, "host", "target")
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))

    def _paths(self) -> set[str]:
        return {urlparse(item.url).path or "/" for item in getattr(self.state, "urls", {}).values()}

    def _param_kinds(self) -> dict[str, int]:
        kinds: dict[str, int] = {}
        for param in getattr(self.state, "params", {}).values():
            kind = str(getattr(param, "kind", "generic"))
            kinds[kind] = kinds.get(kind, 0) + 1
        return kinds

    def _tests_by_name(self) -> dict[str, int]:
        tests: dict[str, int] = {}
        for test in getattr(self.state, "tests", {}).values():
            name = str(getattr(test, "test_name", "unknown"))
            tests[name] = tests.get(name, 0) + 1
        return tests

    def build(self) -> dict[str, Any]:
        urls = getattr(self.state, "urls", {})
        params = getattr(self.state, "params", {})
        tests = getattr(self.state, "tests", {})
        findings = getattr(self.state, "findings", [])
        param_kinds = self._param_kinds()
        tests_by_name = self._tests_by_name()
        gaps: list[str] = []
        if not urls:
            gaps.append("No URLs were discovered. Check target reachability, scope, and request budget.")
        if not params:
            gaps.append("No GET parameters or form-derived inputs were discovered. Use authenticated seeds or add VULNSCOPE_SEED_URLS for deeper coverage.")
        if params and not tests:
            gaps.append("Inputs were discovered but no safe validation tests were recorded.")
        if self.dynamic_ready == 0:
            gaps.append("No ready dynamic tools were available. Run the suite integrator and approve only tools with known safe profiles.")
        auth_review = []
        for param in params.values():
            kind = str(getattr(param, "kind", ""))
            if kind in {"object-like", "reference-like", "route-like", "resource-like"}:
                auth_review.append({"name": getattr(param, "name", ""), "kind": kind, "url": getattr(param, "url", ""), "risk_score": getattr(param, "risk_score", 0), "status": "manual approved-account review required"})
        lab_allowed = self.mode == "lab"
        phase_rows = []
        for name, description in self.PHASES:
            if name == "lab_attack_chain" and not lab_allowed:
                status = "gated"
                reason = "lab mode not enabled"
            elif name == "dynamic_tooling" and self.dynamic_ready == 0:
                status = "not_ready"
                reason = "no enabled approved configured dynamic tools"
            elif name == "auth_boundary_review" and not auth_review:
                status = "inactive"
                reason = "no object/reference/route/resource-like parameters discovered"
            else:
                status = "covered"
                reason = "evidence available or phase applicable"
            phase_rows.append({"phase": name, "status": status, "description": description, "reason": reason})
        return {"target": getattr(self.state, "target", ""), "host": self.host, "mode": self.mode, "include_subdomains": self.include_subdomains, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "coverage": {"urls": len(urls), "paths": len(self._paths()), "params": len(params), "tests": len(tests), "findings": len(findings), "requests": int(getattr(self.state, "stats", {}).get("requests", 0)), "param_kinds": param_kinds, "tests_by_name": tests_by_name, "dynamic_ready": self.dynamic_ready}, "phases": phase_rows, "auth_boundary_review": auth_review[:200], "coverage_gaps": gaps, "rules": {"real_targets": "reconnaissance, safe validation, evidence, and reporting only", "lab_targets": "approved lab validation can be chained into manual attack-path review", "not_automated": "credential attacks, persistence, destructive actions, and unsupervised privilege escalation"}}

    def write(self) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = self.build()
        json_path = self.out_dir / "ethical-methodology-ledger.json"
        md_path = self.out_dir / "ethical-methodology-ledger.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# VulnScope Ethical Methodology Ledger", "", f"Target: `{payload['target']}`", f"Mode: `{payload['mode']}`", f"Scope host: `{payload['host']}` include_subdomains=`{payload['include_subdomains']}`", "", "## Coverage", ""]
        for key, value in payload["coverage"].items():
            lines.append(f"- {key}: `{value}`")
        lines.extend(["", "## Phases", ""])
        for phase in payload["phases"]:
            lines.append(f"- **{phase['phase']}** — `{phase['status']}` — {phase['reason']}")
        lines.extend(["", "## Auth / Privilege Boundary Review", ""])
        if not payload["auth_boundary_review"]:
            lines.append("No object/reference/route/resource-like parameters were discovered for approved-account boundary review.")
        else:
            for item in payload["auth_boundary_review"][:80]:
                lines.append(f"- `{item['name']}` kind=`{item['kind']}` risk=`{item['risk_score']}` url=`{item['url']}` status=`{item['status']}`")
        lines.extend(["", "## Coverage Gaps", ""])
        if not payload["coverage_gaps"]:
            lines.append("No critical methodology gaps were detected from stored scan state.")
        else:
            for gap in payload["coverage_gaps"]:
                lines.append(f"- {gap}")
        lines.extend(["", "## Safety Rules", ""])
        for key, value in payload["rules"].items():
            lines.append(f"- {key}: {value}")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"ethical_methodology_json": str(json_path), "ethical_methodology_md": str(md_path)}
