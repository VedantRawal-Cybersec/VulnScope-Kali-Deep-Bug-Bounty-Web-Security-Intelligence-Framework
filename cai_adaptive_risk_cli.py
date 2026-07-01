#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from typing import Any

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target

BUSINESS_HINTS = {
    "payment": 1.25,
    "billing": 1.25,
    "invoice": 1.2,
    "order": 1.15,
    "account": 1.2,
    "profile": 1.1,
    "admin": 1.3,
    "public-page": 0.8,
}


def _load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return handled_error(component="adaptive_risk", action="load_" + path.name, error=exc, fallback_used="empty_source")


def _business_multiplier(row: dict[str, Any]) -> float:
    text = json.dumps(row, ensure_ascii=False).lower()
    mult = 1.0
    for key, value in BUSINESS_HINTS.items():
        if key in text:
            mult = max(mult, value)
    return mult


def build_adaptive_risk(target: str, *, criticality: str = "normal") -> dict[str, Any]:
    target = normalize_target(target)
    out_dir = cai_output_dir(target)
    priorities = _load(out_dir / "prioritized-findings.json")
    matrix = _load(out_dir / "hypothesis-matrix.json")
    items = [x for x in (priorities.get("prioritized_items", []) if isinstance(priorities, dict) else []) if isinstance(x, dict)]
    crit_mult = {"low": 0.8, "normal": 1.0, "high": 1.2, "critical": 1.4}.get(criticality, 1.0)
    scored = []
    for item in items:
        base = float(item.get("priority_score") or 0.0)
        multiplier = _business_multiplier(item) * crit_mult
        scored.append({**item, "adaptive_risk_score": round(base * multiplier, 3), "business_multiplier": round(multiplier, 3), "user_criticality": criticality})
    scored.sort(key=lambda x: x.get("adaptive_risk_score", 0), reverse=True)
    hypothesis_count = len(matrix.get("hypotheses", []) or []) if isinstance(matrix, dict) else 0
    prediction_rows = []
    if isinstance(matrix, dict):
        for row in matrix.get("hypotheses", [])[:100]:
            prediction_rows.append({
                "endpoint": row.get("endpoint"),
                "topic": row.get("review_topic"),
                "input_type": row.get("input_type"),
                "prediction_score": row.get("priority_score"),
                "reason": "High value review candidate based on input type, context, and review cost.",
            })
    return {
        "target": target,
        "generated_at": time.time(),
        "feature": "Predictive Modeling and Adaptive Risk Scoring",
        "summary": {"risk_items": len(scored), "prediction_candidates": hypothesis_count, "criticality": criticality},
        "adaptive_risk_items": scored,
        "prediction_candidates": prediction_rows,
        "safety": {"new_requests_sent": False, "state_change": False, "notes": "Adaptive risk scoring uses local metadata and evidence only."},
    }


def write_adaptive_risk_reports(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "adaptive-risk.json", payload)
    checkpoint = {"checkpoint": "advanced-risk", "name": "Predictive Modeling and Adaptive Risk Scoring", "status": "completed", "target": target, "summary": payload.get("summary", {}), "reports": {"json": str(out_dir / "adaptive-risk.json"), "markdown": str(out_dir / "adaptive-risk.md")}, "generated_at": time.time()}
    write_json(out_dir / "checkpoint-adaptive-risk.json", checkpoint)
    lines = ["# CAI Advanced Feature — Adaptive Risk", "", f"Target: `{target}`", "", "## Summary", "```json", json.dumps(payload.get("summary", {}), indent=2, ensure_ascii=False), "```", "", "## Top Risk Items"]
    for row in payload.get("adaptive_risk_items", [])[:100]:
        lines.append(f"- risk=`{row.get('adaptive_risk_score')}` class=`{row.get('classification')}` type=`{row.get('vulnerability_type')}` where=`{row.get('where_found')}`")
    lines += ["", "## Prediction Candidates"]
    for row in payload.get("prediction_candidates", [])[:100]:
        lines.append(f"- score=`{row.get('prediction_score')}` topic=`{row.get('topic')}` endpoint=`{row.get('endpoint')}`")
    write_markdown(out_dir / "adaptive-risk.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI adaptive risk scoring")
    parser.add_argument("--target", required=True)
    parser.add_argument("--criticality", default="normal", choices=["low", "normal", "high", "critical"])
    args = parser.parse_args()
    payload = build_adaptive_risk(args.target, criticality=args.criticality)
    print(json.dumps(write_adaptive_risk_reports(args.target, payload), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
