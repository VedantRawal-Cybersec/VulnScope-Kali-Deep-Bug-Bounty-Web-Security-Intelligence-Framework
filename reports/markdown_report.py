from __future__ import annotations

from pathlib import Path

from core.evidence_store import EvidenceStore


def generate_markdown_report(store: EvidenceStore, output_path: Path, target_url: str, mode: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    lines.append("# VulnScope-Kali Security Intelligence Report")
    lines.append("")
    lines.append(f"**Target:** `{target_url}`")
    lines.append(f"**Mode:** `{mode}`")
    lines.append("**Status:** Phase 1 safe assessment")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("This report summarizes passive and safe-active observations collected by VulnScope-Kali. Findings marked as potential or manual-review-required must be validated manually before being submitted to any bug bounty program or client.")
    lines.append("")
    lines.append("## Scan Metrics")
    lines.append("")
    lines.append(f"- Endpoints discovered: `{len(store.endpoints)}`")
    lines.append(f"- Forms detected: `{len(store.forms)}`")
    lines.append(f"- Parameters identified: `{store.metadata.get('parameters_identified', 0)}`")
    lines.append(f"- JavaScript files discovered: `{store.metadata.get('javascript_files_discovered', 0)}`")
    lines.append(f"- JavaScript endpoints discovered: `{store.metadata.get('javascript_endpoints_discovered', 0)}`")
    lines.append(f"- Findings generated: `{len(store.findings)}`")
    lines.append("")

    lines.append("## Findings Summary")
    lines.append("")
    if store.findings:
        lines.append("| ID | Finding | Category | Endpoint | Severity | Confidence | Status |")
        lines.append("|---|---|---|---|---|---|---|")
        for finding in store.findings:
            endpoint = finding.endpoint.replace("|", "%7C")
            lines.append(
                f"| {finding.finding_id} | {finding.title} | {finding.category} | `{endpoint}` | {finding.severity} | {finding.confidence} | {finding.status} |"
            )
    else:
        lines.append("No findings were generated in this run.")
    lines.append("")

    for finding in store.findings:
        lines.append(f"## {finding.finding_id} - {finding.title}")
        lines.append("")
        lines.append(f"- **Category:** {finding.category}")
        lines.append(f"- **Severity:** {finding.severity}")
        lines.append(f"- **Confidence:** {finding.confidence}")
        lines.append(f"- **Status:** {finding.status}")
        lines.append(f"- **Affected Endpoint:** `{finding.endpoint}`")
        if finding.parameter:
            lines.append(f"- **Parameter:** `{finding.parameter}`")
        lines.append(f"- **Where Found:** {finding.where_found}")
        lines.append("")
        lines.append("### How It Was Detected")
        for item in finding.how_detected:
            lines.append(f"- {item}")
        lines.append("")
        lines.append("### Why It Matters")
        lines.append(finding.why_risky or "Manual review required.")
        lines.append("")
        lines.append("### Evidence")
        lines.append("```json")
        lines.append(_safe_json_like(finding.evidence))
        lines.append("```")
        lines.append("")
        lines.append("### Recommended Validation")
        for item in finding.recommended_validation:
            lines.append(f"- {item}")
        lines.append("")
        lines.append("### Suggested Remediation")
        for item in finding.remediation:
            lines.append(f"- {item}")
        lines.append("")

    lines.append("## Discovered Endpoints")
    lines.append("")
    for endpoint in sorted(store.endpoints)[:200]:
        lines.append(f"- `{endpoint}`")
    lines.append("")

    lines.append("## Important Note")
    lines.append("")
    lines.append("This report is for authorized security testing only. Potential findings require manual validation and must be handled according to the target program scope and rules.")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def _safe_json_like(value: object) -> str:
    import json

    return json.dumps(value, indent=2, ensure_ascii=False)
