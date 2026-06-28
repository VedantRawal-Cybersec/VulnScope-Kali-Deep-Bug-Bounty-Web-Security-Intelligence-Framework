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
    findings = load_findings_from_reports([
        "reports/output/agent_core/agent-core-summary.json",
        "reports/output/workflow/reportability-scores.json",
        "reports/output/imports/har-import.json",
    ])
    quality = reduce_low_quality(findings)
    Path("reports/output/finding-quality.json").write_text(json.dumps(quality, indent=2, ensure_ascii=False), encoding="utf-8")
    title_target = target or agent.get("target") or "authorized-target"
    md = _markdown(title_target, agent, council, workflow, quality)
    json_out = OUT / "executive-report-v2.json"
    md_out = OUT / "executive-report-v2.md"
    json_out.write_text(json.dumps({"target": title_target, "agent_summary": agent, "quality": quality, "council": council}, indent=2, ensure_ascii=False), encoding="utf-8")
    md_out.write_text(md, encoding="utf-8")
    return {"markdown": md_out, "json": json_out}


def _markdown(target: str, agent: dict[str, Any], council: str, workflow: str, quality: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).isoformat()
    accepted = quality.get("accepted", [])
    review = quality.get("needs_review", [])
    lines = [
        f"# VulnScope Report v2 — {target}",
        "",
        f"Generated: `{now}`",
        "",
        "## Scope and Safety Statement",
        "This report is for owned or explicitly authorized assets only. Findings are evidence-first and require manual validation before submission.",
        "",
        "## Executive Summary",
        f"- Tool stages: `{len(agent.get('tool_results', []))}`",
        f"- Specialist agent results: `{len(agent.get('agent_results', []))}`",
        f"- Accepted high-quality candidates: `{len(accepted)}`",
        f"- Needs review: `{len(review)}`",
        "",
        "## High-Quality Candidates",
    ]
    if not accepted:
        lines.append("No high-quality candidates were accepted by the quality engine yet.")
    for item in accepted[:25]:
        lines += [
            f"### {item.get('title', item.get('category', 'Candidate'))}",
            f"- Category: `{item.get('category', 'unknown')}`",
            f"- URL: `{item.get('url', item.get('endpoint', 'n/a'))}`",
            f"- Quality score: `{item.get('quality_score')}`",
            f"- Notes: `{'; '.join(item.get('quality_notes', []))}`",
            "",
        ]
    lines += ["## Model Council Consensus", council or "No model-council consensus generated.", "", "## Original Workflow Notes", workflow[:6000] if workflow else "No workflow report found."]
    return "\n".join(lines)
