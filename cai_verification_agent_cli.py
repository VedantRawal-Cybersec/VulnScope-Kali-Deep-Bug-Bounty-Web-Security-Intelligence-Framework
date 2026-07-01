#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target

EVIDENCE_SOURCES = [
    Path("reports/output/safe-canary/safe-probes.json"),
    Path("reports/output/safe-canary/safe-canary.json"),
    Path("reports/output/final-dashboard"),
]


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return handled_error(component="verification_agent", action="load_json", error=exc, fallback_used="source_unavailable")


def load_hypotheses(target: str) -> dict[str, Any]:
    path = cai_output_dir(target) / "hypothesis-matrix.json"
    data = load_json(path)
    return data if isinstance(data, dict) else {"hypotheses": []}


def collect_existing_evidence(target: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    slug = cai_output_dir(target).name
    for source in EVIDENCE_SOURCES:
        if source.is_dir():
            for path in source.glob(f"{slug}-*.json"):
                data = load_json(path)
                if isinstance(data, dict):
                    rows.extend(data.get("findings", []) or data.get("review_leads", []) or data.get("surface_findings", []) or [])
            continue
        data = load_json(source)
        if isinstance(data, dict):
            rows.extend(data.get("findings", []) or data.get("review_leads", []) or data.get("surface_findings", []) or [])
    return [r for r in rows if isinstance(r, dict)]


def evidence_match(hypothesis: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any] | None:
    endpoint = str(hypothesis.get("endpoint") or "").lower()
    input_name = str(hypothesis.get("input_name") or "").lower()
    for row in evidence:
        blob = json.dumps(row, ensure_ascii=False).lower()
        if endpoint and endpoint in blob:
            return row
        if input_name and input_name != "n/a" and input_name in blob:
            return row
    return None


def verify_from_existing_evidence(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    hypotheses = load_hypotheses(target)
    evidence = collect_existing_evidence(target)
    rows: list[dict[str, Any]] = []
    for item in hypotheses.get("hypotheses", [])[:500]:
        match = evidence_match(item, evidence)
        if match:
            rows.append({
                "hypothesis": item,
                "status": "evidence_observed",
                "initial_confidence": "medium",
                "observed_behavior": str(match.get("evidence") or match.get("evidence_detail") or match.get("confirmation_status") or "existing evidence artifact matched")[:700],
                "source": match.get("source") or "existing_report",
            })
        else:
            rows.append({
                "hypothesis": item,
                "status": "needs_more_signal",
                "initial_confidence": "low",
                "observed_behavior": "No existing comparable evidence artifact matched this hypothesis.",
                "source": "none",
            })
    return {
        "target": target,
        "generated_at": time.time(),
        "layer": 4,
        "mode": "evidence-only-verification",
        "summary": {
            "tested_hypotheses": len(rows),
            "evidence_observed": len([r for r in rows if r.get("status") == "evidence_observed"]),
            "needs_more_signal": len([r for r in rows if r.get("status") == "needs_more_signal"]),
            "evidence_sources_loaded": len(evidence),
        },
        "results": rows,
        "safety": {"new_requests_sent": False, "state_change": False, "notes": "Layer 4 uses existing safe evidence artifacts only and does not send target requests."},
    }


def write_verification_reports(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "verification-results.json", payload)
    checkpoint = {"checkpoint": 4, "name": "Non-Intrusive Verification Agent", "status": "completed", "target": target, "summary": payload.get("summary", {}), "reports": {"json": str(out_dir / "verification-results.json"), "markdown": str(out_dir / "verification-results.md")}, "generated_at": time.time()}
    write_json(out_dir / "checkpoint-4.json", checkpoint)
    lines = ["# CAI Superior Checkpoint 4 — Non-Intrusive Verification", "", f"Target: `{target}`", f"Hypotheses reviewed: `{payload.get('summary', {}).get('tested_hypotheses', 0)}`", f"Evidence observed: `{payload.get('summary', {}).get('evidence_observed', 0)}`", f"Needs more signal: `{payload.get('summary', {}).get('needs_more_signal', 0)}`", "", "## Results"]
    for row in payload.get("results", [])[:250]:
        h = row.get("hypothesis", {})
        lines.append(f"- status=`{row.get('status')}` confidence=`{row.get('initial_confidence')}` topic=`{h.get('review_topic')}` input=`{h.get('input_name')}` endpoint=`{h.get('endpoint')}`")
    write_markdown(out_dir / "verification-results.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI Superior Layer 4 evidence-only verification")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    payload = verify_from_existing_evidence(args.target)
    print(json.dumps(write_verification_reports(args.target, payload), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
