#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target
from core.scan_state import ScanState


SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|authorization|cookie|session|password)=([^\s&;]+)"),
]


def clean_text(value: Any, limit: int = 600) -> str:
    text = str(value if value is not None else "").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = re.sub(r"\s+", " ", text).strip()
    for pattern in SENSITIVE_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    if len(text) > limit:
        return text[: max(0, limit - 1)] + "…"
    return text or "N/A"


def status_bucket(status: Any) -> str:
    normalized = str(status or "Review Lead").strip().lower().replace("_", " ")
    if normalized == "confirmed":
        return "CONFIRMED BUG / OBSERVATION"
    if normalized in {"informational", "info"}:
        return "INFORMATIONAL OBSERVATION"
    return "MANUAL REVIEW LEAD"


def cvss_style_reason(severity: Any, confidence: Any, status: Any) -> str:
    sev = str(severity or "INFO").upper()
    bucket = status_bucket(status)
    try:
        conf = int(confidence or 0)
    except Exception:
        conf = 0
    if bucket.startswith("CONFIRMED") and sev in {"CRITICAL", "HIGH"}:
        return f"{sev}: confirmed behavior with high business/security impact; confidence {conf}%."
    if bucket.startswith("CONFIRMED") and sev == "MEDIUM":
        return f"MEDIUM: confirmed behavior that may affect security if reachable in an exploitable workflow; confidence {conf}%."
    if bucket.startswith("CONFIRMED"):
        return f"{sev}: confirmed low-impact or hardening observation; confidence {conf}%."
    if bucket.startswith("MANUAL"):
        return f"{sev}: not confirmed as exploitable; flagged because the parameter or route pattern needs authorized manual validation; confidence {conf}%."
    return f"{sev}: informational hardening or exposure note; confidence {conf}%."


def safe_next_action(finding: dict[str, Any]) -> str:
    status = str(finding.get("status") or "").lower()
    category = str(finding.get("category") or "").lower()
    if status == "confirmed" and "reflection" in category:
        return "Review output encoding and context. Validate only with harmless canaries inside authorized scope. Do not attempt script execution on production."
    if "redirect" in category:
        return "Check destination allowlisting and normalization in staging or an approved test account. Do not test external redirect abuse on production."
    if "parameter" in category:
        return "Validate server-side authorization/validation with approved accounts or staging. Keep production checks low-impact."
    if "header" in category or "cookie" in category or "csp" in category:
        return "Treat as hardening unless tied to a reachable exploit chain. Apply configuration fix and re-run passive verification."
    return "Review the captured evidence, reproduce only in the authorized scope, and document impact before claiming exploitability."


class ReportingV2:
    def __init__(self, *, state: ScanState, extra_reports: dict[str, str] | None = None) -> None:
        self.state = state
        self.target = normalize_target(state.target)
        self.out = cai_output_dir(self.target)
        self.extra_reports = extra_reports or {}

    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.state.findings:
            sev = str(finding.get("severity") or "INFO").upper()
            counts[sev if sev in counts else "INFO"] += 1
        return counts

    def directed_finding_card(self, finding: dict[str, Any], index: int) -> dict[str, Any]:
        affected_url = clean_text(finding.get("affected_url") or finding.get("url") or self.target, 1000)
        parsed = urlparse(affected_url if affected_url != "N/A" else self.target)
        parameter = clean_text(finding.get("parameter") or "N/A", 200)
        request_line = "GET " + (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        status = clean_text(finding.get("status") or "Review Lead", 80)
        severity = clean_text(finding.get("severity") or "INFO", 40).upper()
        confidence = clean_text(str(finding.get("confidence") if finding.get("confidence") is not None else "N/A") + ("%" if str(finding.get("confidence") or "").isdigit() else ""), 40)
        title = clean_text(finding.get("title") or "Security Finding", 220)
        evidence = clean_text(finding.get("evidence") or "No evidence text recorded.", 1400)
        impact = clean_text(finding.get("impact") or "Impact requires analyst validation.", 1000)
        recommendation = clean_text(finding.get("recommendation") or "Review and remediate according to application context.", 1000)
        probe = clean_text(finding.get("safe_probe") or finding.get("probe") or "N/A", 220)
        category = clean_text(finding.get("category") or "General", 120)
        steps = [clean_text(step, 500) for step in (finding.get("reproduction_steps") or [])[:8]] or ["Review the evidence artifact inside the authorized scope."]
        return {
            "number": index,
            "id": clean_text(finding.get("id") or f"finding-{index}", 120),
            "status_bucket": status_bucket(status),
            "status": status,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "what": title,
            "where": {
                "url": affected_url,
                "request": request_line,
                "path": clean_text(parsed.path or "/", 300),
                "parameter": parameter,
                "safe_probe": probe,
            },
            "why": evidence,
            "impact": impact,
            "severity_reason": cvss_style_reason(severity, finding.get("confidence"), status),
            "safe_validation": steps,
            "fix": recommendation,
            "next_safe_action": safe_next_action(finding),
        }

    def directed_cards(self) -> list[dict[str, Any]]:
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings = sorted(
            self.state.findings,
            key=lambda item: (
                severity_rank.get(str(item.get("severity") or "INFO").upper(), 4),
                -int(item.get("confidence") or 0),
                str(item.get("title") or ""),
            ),
        )
        return [self.directed_finding_card(finding, idx) for idx, finding in enumerate(findings, 1)]

    def write_json_report(self) -> Path:
        path = self.out / "autonomous-scan-report.json"
        payload = {
            "target": self.target,
            "coverage": self.state.coverage(),
            "severity_counts": self.severity_counts(),
            "directed_findings": self.directed_cards(),
            "findings": self.state.findings,
            "parameters": [vars(item) for item in self.state.params.values()],
            "urls": [vars(item) for item in self.state.urls.values()],
            "tests": [vars(item) for item in self.state.tests.values()],
            "reports": self.extra_reports,
            "safety": {
                "same_scope_only": True,
                "transparent_user_agent": True,
                "request_budget": True,
                "adaptive_backoff": True,
                "resume_supported": True,
                "target_data_modification": False,
            },
        }
        write_json(path, payload)
        return path

    def write_directed_findings_json(self) -> Path:
        path = self.out / "final-findings-dashboard.json"
        payload = {
            "target": self.target,
            "coverage": self.state.coverage(),
            "severity_counts": self.severity_counts(),
            "findings_total": len(self.state.findings),
            "dashboard_schema": "what_where_why_evidence_impact_fix",
            "findings": self.directed_cards(),
        }
        write_json(path, payload)
        return path

    def final_dashboard_lines(self) -> list[str]:
        cov = self.state.coverage()
        counts = self.severity_counts()
        cards = self.directed_cards()
        lines = [
            "# VulnScope Final Findings Dashboard",
            "",
            f"Target: `{self.target}`",
            "",
            "## Scan Coverage",
            "",
            f"- URLs completed: `{cov['urls_done']}/{cov['urls_total']}`",
            f"- Parameters completed: `{cov['params_done']}/{cov['params_total']}`",
            f"- Tests completed: `{cov['tests_done']}/{cov['tests_total']}`",
            f"- Requests: `{cov['requests']}`",
            f"- Timeouts: `{cov['timeouts']}`",
            f"- Findings / review leads: `{cov['findings']}`",
            "",
            "## Severity Counts",
            "",
            f"`CRITICAL:{counts['CRITICAL']}` `HIGH:{counts['HIGH']}` `MEDIUM:{counts['MEDIUM']}` `LOW:{counts['LOW']}` `INFO:{counts['INFO']}`",
            "",
            "## Directed Finding Cards",
            "",
        ]
        if not cards:
            lines += [
                "No confirmed findings or review leads were generated in the selected safe scope.",
                "",
                "This does not prove the application is vulnerability-free. It only means VulnScope did not collect evidence strong enough to create a finding under the selected mode, scope, and request budget.",
            ]
            return lines
        for card in cards:
            lines += [
                f"### Finding #{card['number']} — {card['severity']} — {card['status_bucket']}",
                "",
                f"**WHAT:** {card['what']}",
                "",
                f"**WHERE:** `{card['where']['url']}`",
                f"- Request: `{card['where']['request']}`",
                f"- Path: `{card['where']['path']}`",
                f"- Parameter: `{card['where']['parameter']}`",
                f"- Safe probe: `{card['where']['safe_probe']}`",
                "",
                f"**WHY THIS WAS FLAGGED:** {card['why']}",
                "",
                f"**IMPACT:** {card['impact']}",
                "",
                f"**SEVERITY / CONFIDENCE:** `{card['severity']}` with confidence `{card['confidence']}`. {card['severity_reason']}",
                "",
                "**SAFE VALIDATION STEPS:**",
            ]
            for step in card["safe_validation"]:
                lines.append(f"- {step}")
            lines += [
                "",
                f"**FIX:** {card['fix']}",
                "",
                f"**NEXT SAFE ACTION:** {card['next_safe_action']}",
                "",
                "---",
                "",
            ]
        return lines

    def write_final_findings_dashboard_md(self) -> Path:
        path = self.out / "final-findings-dashboard.md"
        write_markdown(path, self.final_dashboard_lines())
        return path

    def write_final_findings_dashboard_txt(self) -> Path:
        path = self.out / "final-findings-dashboard.txt"
        text_lines = []
        for line in self.final_dashboard_lines():
            cleaned = line.replace("**", "").replace("`", "")
            if cleaned.startswith("# "):
                cleaned = cleaned[2:].upper()
            if cleaned.startswith("## "):
                cleaned = "\n" + cleaned[3:].upper()
            if cleaned.startswith("### "):
                cleaned = "\n" + "=" * 100 + "\n" + cleaned[4:].upper() + "\n" + "=" * 100
            text_lines.append(cleaned)
        path.write_text("\n".join(text_lines), encoding="utf-8")
        return path

    def write_markdown_report(self) -> Path:
        path = self.out / "autonomous-scan-report.md"
        cov = self.state.coverage()
        counts = self.severity_counts()
        lines = [
            "# VulnScope Autonomous Scan Report",
            "",
            f"Target: `{self.target}`",
            "",
            "## Coverage",
            "",
            f"- URLs: `{cov['urls_done']}/{cov['urls_total']}`",
            f"- Parameters: `{cov['params_done']}/{cov['params_total']}`",
            f"- Tests: `{cov['tests_done']}/{cov['tests_total']}`",
            f"- Requests: `{cov['requests']}`",
            f"- Timeouts: `{cov['timeouts']}`",
            f"- Findings/leads: `{cov['findings']}`",
            "",
            "## Severity Summary",
            "",
        ]
        for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"- `{key}`: `{counts[key]}`")
        lines += ["", "## Final Directed Findings Dashboard", "", "Open `final-findings-dashboard.md` for the clean WHAT / WHERE / WHY / EVIDENCE / IMPACT / FIX view.", "", "## Findings and Review Leads", ""]
        if not self.state.findings:
            lines.append("No confirmed findings or review leads were generated in the selected safe scope.")
        for card in self.directed_cards():
            lines.extend([
                f"### Finding #{card['number']} — {card['what']}",
                f"- Status: `{card['status_bucket']}`",
                f"- Severity: `{card['severity']}`",
                f"- Confidence: `{card['confidence']}`",
                f"- Category: `{card['category']}`",
                f"- WHAT: {card['what']}",
                f"- WHERE: `{card['where']['url']}`",
                f"- REQUEST: `{card['where']['request']}`",
                f"- PARAMETER: `{card['where']['parameter']}`",
                f"- WHY: {card['why']}",
                f"- IMPACT: {card['impact']}",
                f"- FIX: {card['fix']}",
                f"- NEXT SAFE ACTION: {card['next_safe_action']}",
                "",
            ])
        lines += ["## Top Parameter Inventory", ""]
        for param in sorted(self.state.params.values(), key=lambda p: p.risk_score, reverse=True)[:100]:
            lines.append(f"- `{param.name}` kind=`{param.kind}` risk=`{param.risk_score}` status=`{param.status}` source=`{param.source}` url=`{param.url}`")
        if self.extra_reports:
            lines += ["", "## Additional Artifacts", ""]
            for name, report_path in self.extra_reports.items():
                lines.append(f"- `{name}`: `{report_path}`")
        write_markdown(path, lines)
        return path

    def write_csv_findings(self) -> Path:
        path = self.out / "autonomous-findings.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = ["id", "title", "status", "severity", "confidence", "category", "affected_url", "parameter", "evidence", "impact", "recommendation", "next_safe_action"]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for card in self.directed_cards():
                writer.writerow({
                    "id": card["id"],
                    "title": card["what"],
                    "status": card["status_bucket"],
                    "severity": card["severity"],
                    "confidence": card["confidence"],
                    "category": card["category"],
                    "affected_url": card["where"]["url"],
                    "parameter": card["where"]["parameter"],
                    "evidence": card["why"],
                    "impact": card["impact"],
                    "recommendation": card["fix"],
                    "next_safe_action": card["next_safe_action"],
                })
        return path

    def write_parameter_inventory(self) -> Path:
        path = self.out / "parameter-inventory-v2.json"
        write_json(path, [vars(item) for item in self.state.params.values()])
        return path

    def write_all(self) -> dict[str, str]:
        self.state.save()
        state_md = self.state.write_markdown_summary()
        final_dashboard_md = self.write_final_findings_dashboard_md()
        final_dashboard_json = self.write_directed_findings_json()
        final_dashboard_txt = self.write_final_findings_dashboard_txt()
        return {
            "autonomous_report_json": str(self.write_json_report()),
            "autonomous_report_md": str(self.write_markdown_report()),
            "final_findings_dashboard_md": str(final_dashboard_md),
            "final_findings_dashboard_json": str(final_dashboard_json),
            "final_findings_dashboard_txt": str(final_dashboard_txt),
            "autonomous_findings_csv": str(self.write_csv_findings()),
            "parameter_inventory_v2": str(self.write_parameter_inventory()),
            "autonomous_state_json": str(self.state.path),
            "autonomous_state_md": str(state_md),
            **self.extra_reports,
        }
