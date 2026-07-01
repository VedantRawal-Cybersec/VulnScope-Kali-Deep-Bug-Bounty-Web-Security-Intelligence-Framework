#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target

PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "immunefi"]


def _load_prioritized(target: str) -> dict[str, Any]:
    path = cai_output_dir(target) / "prioritized-findings.json"
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return {"prioritized_items": [], "load_error": handled_error(component="report_agent", action="load_prioritized", error=exc, fallback_used="empty_priorities")}


def _severity(row: dict[str, Any]) -> str:
    priority = float(row.get("priority_score") or 0.0)
    if row.get("classification") != "CONFIRMED":
        return "Informational / Review Lead"
    if priority >= 140:
        return "Critical"
    if priority >= 120:
        return "High"
    if priority >= 90:
        return "Medium"
    return "Low"


def _cvss(row: dict[str, Any]) -> dict[str, str]:
    severity = _severity(row)
    if severity == "Critical":
        return {"score": "9.0", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N"}
    if severity == "High":
        return {"score": "8.1", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}
    if severity == "Medium":
        return {"score": "5.3", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}
    if severity == "Low":
        return {"score": "3.1", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}
    return {"score": "0.0", "vector": "Review lead only - CVSS deferred until confirmed evidence is available"}


def _report_body(target: str, row: dict[str, Any], platform: str) -> str:
    cvss = _cvss(row)
    title = row.get("what_found") or row.get("vulnerability_type") or "Security review item"
    where = row.get("where_found") or target
    evidence = row.get("evidence_detail") or row.get("evidence") or "Evidence artifact unavailable."
    confidence = row.get("confidence") or "unknown"
    classification = row.get("classification") or "REVIEW LEAD"
    remediation = "Review server-side authorization, input handling, and response controls for the affected endpoint. Confirm intended behavior, then apply least-privilege checks and regression tests."
    if classification != "CONFIRMED":
        remediation = "Do not submit as a confirmed issue yet. Collect additional authorized baseline and reproduction evidence first."
    return "\n".join([
        f"# {title}",
        "",
        f"Platform format: {platform}",
        f"Target: {target}",
        f"Classification: {classification}",
        f"Severity: {_severity(row)}",
        f"Confidence: {confidence}",
        f"Confidence score: {row.get('confidence_score', 'n/a')}",
        f"CVSS 4.0: {cvss['score']}",
        f"Vector: {cvss['vector']}",
        "",
        "## Affected location",
        f"`{where}`",
        "",
        "## Evidence",
        evidence,
        "",
        "## Safe reproduction path",
        "1. Use only the already authorized target scope.",
        "2. Reproduce the same safe comparison or baseline request recorded by VulnScope.",
        "3. Confirm the evidence artifact and compare against the control result.",
        "4. Do not use destructive methods or state-changing payloads.",
        "",
        "## Control comparison",
        str(row.get("control_comparison_result") or "No explicit control comparison available."),
        "",
        "## Impact assessment",
        str(row.get("false_positive_risk_notes") or "Impact requires final human review."),
        "",
        "## Recommended remediation",
        remediation,
    ])


def build_reports(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    data = _load_prioritized(target)
    items = [x for x in data.get("prioritized_items", []) or [] if isinstance(x, dict)]
    reports: list[dict[str, Any]] = []
    for idx, row in enumerate(items[:80], 1):
        platform_bodies = {p: _report_body(target, row, p) for p in PLATFORMS}
        reports.append({
            "id": f"CAI-REPORT-{idx:03d}",
            "classification": row.get("classification"),
            "severity": _severity(row),
            "title": row.get("what_found") or row.get("vulnerability_type"),
            "where_found": row.get("where_found"),
            "confidence": row.get("confidence"),
            "confidence_score": row.get("confidence_score"),
            "platform_reports": platform_bodies,
        })
    return {
        "target": target,
        "generated_at": time.time(),
        "layer": 7,
        "name": "Report Generation Agent",
        "summary": {
            "platforms": PLATFORMS,
            "report_items": len(reports),
            "confirmed_reports": len([r for r in reports if r.get("classification") == "CONFIRMED"]),
            "review_lead_reports": len([r for r in reports if r.get("classification") == "REVIEW LEAD"]),
        },
        "reports": reports,
        "safety": {"new_requests_sent": False, "state_change": False, "notes": "Layer 7 formats existing confirmed evidence and review leads only."},
    }


def write_report_outputs(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    reports_dir = out_dir / "platform-reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "submission-reports.json", payload)
    for item in payload.get("reports", []) or []:
        report_id = item.get("id") or "report"
        for platform, body in (item.get("platform_reports", {}) or {}).items():
            (reports_dir / f"{report_id}-{platform}.md").write_text(str(body), encoding="utf-8")
    checkpoint = {"checkpoint": 7, "name": "Report Generation Agent", "status": "completed", "target": target, "summary": payload.get("summary", {}), "reports": {"json": str(out_dir / "submission-reports.json"), "markdown_dir": str(reports_dir)}, "generated_at": time.time()}
    write_json(out_dir / "checkpoint-7.json", checkpoint)
    lines = ["# CAI Checkpoint 7 — Platform Reports", "", f"Target: `{target}`", "", "## Summary", "```json", json.dumps(payload.get("summary", {}), indent=2, ensure_ascii=False), "```", "", "## Generated Report Files"]
    for item in payload.get("reports", [])[:80]:
        for platform in PLATFORMS:
            lines.append(f"- `{reports_dir / (str(item.get('id')) + '-' + platform + '.md')}`")
    write_markdown(out_dir / "submission-reports.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI Layer 7 report generation")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    payload = build_reports(args.target)
    print(json.dumps(write_report_outputs(args.target, payload), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
