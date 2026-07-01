#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from typing import Any

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target

MATRIX = {
    "numeric": [("object-identity-access-review", "High", 7.5, 1), ("enumeration-signal-review", "Medium", 3.0, 2)],
    "opaque-id": [("object-reference-review", "Medium", 6.0, 3)],
    "uuid": [("uuid-structure-review", "Medium", 5.0, 5), ("object-reference-review", "Medium", 6.0, 3)],
    "email": [("account-discovery-signal-review", "High", 3.0, 2)],
    "base64": [("encoded-data-review", "Medium", 6.0, 3)],
    "date": [("range-filter-review", "Low", 3.0, 2)],
    "enum": [("state-and-mode-review", "Medium", 5.0, 3)],
    "url": [("navigation-target-review", "Medium", 6.5, 4), ("remote-resource-reference-review", "Low", 6.5, 5)],
    "file": [("file-reference-review", "Medium", 6.0, 4)],
    "free-text": [("reflection-context-review", "Medium", 4.0, 3)],
    "unknown": [("manual-input-review", "Low", 2.0, 4)],
}
LIKELIHOOD = {"High": 0.9, "Medium": 0.6, "Low": 0.3}


def load_inventory(target: str) -> dict[str, Any]:
    path = cai_output_dir(target) / "input-inventory.json"
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return handled_error(component="hypothesis_agent", action="load_inventory", error=exc, fallback_used="empty_inventory")


def priority(likelihood: str, impact: float, cost: int) -> float:
    return round((LIKELIHOOD.get(likelihood, 0.1) * float(impact)) / max(1, int(cost)), 3)


def generate_hypotheses(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    inventory = load_inventory(target)
    rows: list[dict[str, Any]] = []
    if isinstance(inventory, dict):
        for endpoint in inventory.get("endpoints", []) or []:
            for item in endpoint.get("inputs", []) or []:
                input_type = str(item.get("inferred_type") or "unknown")
                for review_topic, likelihood, impact, cost in MATRIX.get(input_type, MATRIX["unknown"]):
                    rows.append({
                        "endpoint": endpoint.get("url"),
                        "path_template": endpoint.get("path_template"),
                        "endpoint_class": endpoint.get("endpoint_class"),
                        "input_name": item.get("name"),
                        "input_type": input_type,
                        "review_topic": review_topic,
                        "likelihood": likelihood,
                        "impact_estimate": impact,
                        "review_cost": cost,
                        "priority_score": priority(likelihood, impact, cost),
                        "safety": "non-destructive evidence-only validation required",
                    })
    rows.sort(key=lambda r: r.get("priority_score", 0), reverse=True)
    return {
        "target": target,
        "generated_at": time.time(),
        "layer": 3,
        "mode": "hypothesis-ranking",
        "summary": {"hypotheses": len(rows), "endpoints_considered": len((inventory or {}).get("endpoints", []) or []) if isinstance(inventory, dict) else 0},
        "hypotheses": rows,
        "safety": {"new_requests_sent": False, "state_change": False, "notes": "Layer 3 ranks review hypotheses only. It does not test them."},
    }


def write_hypothesis_reports(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "hypothesis-matrix.json", payload)
    checkpoint = {"checkpoint": 3, "name": "Hypothesis Generation Agent", "status": "completed", "target": target, "summary": payload.get("summary", {}), "reports": {"json": str(out_dir / "hypothesis-matrix.json"), "markdown": str(out_dir / "hypothesis-matrix.md")}, "generated_at": time.time()}
    write_json(out_dir / "checkpoint-3.json", checkpoint)
    lines = ["# CAI Superior Checkpoint 3 — Hypothesis Matrix", "", f"Target: `{target}`", f"Hypotheses: `{payload.get('summary', {}).get('hypotheses', 0)}`", "", "## Sorted Hypotheses"]
    for row in payload.get("hypotheses", [])[:250]:
        lines.append(f"- score=`{row.get('priority_score')}` topic=`{row.get('review_topic')}` input=`{row.get('input_name')}` type=`{row.get('input_type')}` endpoint=`{row.get('endpoint')}`")
    write_markdown(out_dir / "hypothesis-matrix.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI Superior Layer 3 hypothesis ranking")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    payload = generate_hypotheses(args.target)
    print(json.dumps(write_hypothesis_reports(args.target, payload), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
