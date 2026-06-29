from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from findings.quality import load_findings_from_reports, reduce_low_quality

OUT = Path("reports/output/report-v2")


def _load(path: str) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    if path.endswith(".json"):
        try:
            return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return None
    return p.read_text(encoding="utf-8", errors="ignore")


def build_report_v2(target: str | None = None) -> dict[str, Path]:
    OUT.mkdir(parents=True, exist_ok=True)
    agent = _load("reports/output/agent_core/agent-core-summary.json") or {}
    council = _load("reports/output/agent_core/model-council/council-consensus.md") or ""
    workflow = _load("reports/output/workflow/vulnscope-assessment-report.md") or ""
    safe_discovery = _load("reports/output/safe-discovery/safe-discovery.json") or {}
    comprehensive = _load("reports/output/comprehensive-suite/comprehensive-suite.json") or {}
    google_context = _load("reports/output/auth/google-context/google-context-review.json") or {}
    findings = load_findings_from_reports([
        "reports/output/safe-discovery/safe-discovery.json",
        "reports/output/comprehensive-suite/comprehensive-suite.json",
        "reports/output/auth/google-context/google-context-review.json",
        "reports/output/agent_core/agent-core-summary.json",
        "reports/output/workflow/reportability-scores.json",
        "reports/output/imports/har-import.json",
    ])
    quality = reduce_low_quality(findings)
    Path("reports/output/finding-quality.json").write_text(json.dumps(quality, indent=2, ensure_ascii=False), encoding="utf-8")
    title_target = target or agent.get("target") or safe_discovery.get("target") or comprehensive.get("target") or "authorized-target"
    md = _markdown(title_target, agent, council, workflow, quality, safe_discovery, comprehensive, google_context)
    json_out = OUT / "executive-report-v2.json"
    md_out = OUT / "executive-report-v2.md"
    json_out.write_text(json.dumps({"target": title_target, "agent_summary": agent, "safe_discovery": safe_discovery, "comprehensive_suite": comprehensive, "google_context": google_context, "quality": quality, "council": council}, indent=2, ensure_ascii=False), encoding="utf-8")
    md_out.write_text(md, encoding="utf-8")
    return {"markdown": md_out, "json": json_out}


def _markdown(target: str, agent: dict[str, Any], council: str, workflow: str, quality: dict[str, Any], safe_discovery: dict[str, Any], comprehensive: dict[str, Any], google_context: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).isoformat()
    accepted = quality.get("accepted", [])
    review = quality.get("needs_review", [])
    safe_summary = safe_discovery.get("summary", {}) if isinstance(safe_discovery, dict) else {}
    comp_summary = comprehensive.get("summary", {}) if isinstance(comprehensive, dict) else {}
    google_summary = google_context.get("summary", {}) if isinstance(google_context, dict) else {}
    lines = [
        f"# VulnScope Report v2 — {target}",
        "",
        f"Generated: `{now}`",
        "",
        "## Scope and Safety Statement",
        "This report is for owned or explicitly authorized assets only. Findings are evidence-first review candidates and require manual validation before submission.",
        "",
        "## Executive Summary",
        f"- Tool stages: `{len(agent.get('tool_results', []))}`",
        f"- Specialist agent results: `{len(agent.get('agent_results', []))}`",
        f"- Safe discovery candidates: `{safe_summary.get('findings', 0)}`",
        f"- Comprehensive-suite categories: `{comp_summary.get('categories', 0)}`",
        f"- Comprehensive-suite detectors: `{comp_summary.get('detectors', 0)}`",
        f"- Comprehensive-suite candidates: `{comp_summary.get('candidates', 0)}`",
        f"- Google-context candidates: `{google_summary.get('candidates', 0)}`",
        f"- Accepted high-quality candidates: `{len(accepted)}`",
        f"- Needs review: `{len(review)}`",
        "",
        "## High-Quality Candidates",
    ]
    if not accepted:
        lines.append("No high-quality candidates were accepted by the quality engine yet.")
    for item in accepted[:35]:
        lines += [
            f"### {item.get('title', item.get('category', 'Candidate'))}",
            f"- Category: `{item.get('category', 'unknown')}`",
            f"- URL: `{item.get('url', item.get('endpoint', 'n/a'))}`",
            f"- Quality score: `{item.get('quality_score')}`",
            f"- Notes: `{'; '.join(item.get('quality_notes', []))}`",
            "",
        ]
    lines += [
        "## Comprehensive Review Coverage",
        "Output: `reports/output/comprehensive-suite/comprehensive-suite.md`" if comp_summary else "No comprehensive-suite run found.",
        "",
        "## Google Authenticated Context Review",
        "Output: `reports/output/auth/google-context/google-context-review.md`" if google_summary else "No Google context review run found.",
        "",
        "## Safe Discovery Evidence",
        "Safe Discovery uses low-impact same-origin HEAD/GET checks only and does not confirm impact by itself.",
        "Evidence folder: `reports/output/safe-discovery/evidence/`" if safe_summary else "No safe discovery run found.",
        "",
        "## Model Council Consensus",
        council or "No model-council consensus generated.",
        "",
        "## Original Workflow Notes",
        workflow[:6000] if workflow else "No workflow report found.",
    ]
    return "\n".join(lines)
