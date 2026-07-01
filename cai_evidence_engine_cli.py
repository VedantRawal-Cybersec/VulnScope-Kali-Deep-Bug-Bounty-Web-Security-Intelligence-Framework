#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target
from finding_confirmation_engine import confirm_findings


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return handled_error(component="evidence_engine", action="load_" + path.name, error=exc, fallback_used="empty_source")


def _artifact_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _raw_from_verification(target: str) -> list[dict[str, Any]]:
    path = cai_output_dir(target) / "verification-results.json"
    data = _load(path)
    rows: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return rows
    for item in data.get("results", []) or []:
        hyp = item.get("hypothesis", {}) if isinstance(item, dict) else {}
        endpoint = hyp.get("endpoint") or target
        review_topic = hyp.get("review_topic") or "security-review"
        evidence = item.get("observed_behavior") or "No comparable evidence artifact observed."
        rows.append({
            "source": "CAI evidence review",
            "title": review_topic,
            "type": review_topic,
            "where_found": endpoint,
            "tested_url": endpoint,
            "parameter": hyp.get("input_name") or "n/a",
            "evidence": evidence,
            "control_comparison_result": "Existing safe evidence artifact matched" if item.get("status") == "evidence_observed" else "No existing control evidence matched",
            "status": item.get("status") or "needs_more_signal",
        })
    return rows


def _raw_from_dashboard(target: str) -> list[dict[str, Any]]:
    slug = cai_output_dir(target).name
    path = Path("reports/output/final-dashboard") / f"{slug}-confirmation-engine.json"
    data = _load(path)
    rows: list[dict[str, Any]] = []
    if isinstance(data, dict):
        rows.extend(data.get("surface_findings", []) or [])
        rows.extend(data.get("review_leads", []) or [])
        rows.extend(data.get("findings", []) or [])
    return [x for x in rows if isinstance(x, dict)]


def build_evidence_layer(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    raw = _raw_from_verification(target) + _raw_from_dashboard(target)
    confirmation = confirm_findings(raw, target) if raw else {
        "deduplication": {"raw_count": 0, "unique_count": 0, "dedup_ratio": "0 -> 0", "duplicates_suppressed": 0},
        "summary": {"surface_count": 0, "confirmed": 0, "review_leads": 0, "noise_suppressed": 0, "needs_more_signal": 0, "high_confidence": 0, "medium_confidence": 0, "avg_confidence_score": 0.0},
        "findings": [],
        "review_leads": [],
        "surface_findings": [],
        "suppressed_noise": [],
        "needs_more_signal": [],
    }
    evidence_rows = []
    for row in confirmation.get("surface_findings", []) or []:
        row = dict(row)
        row["evidence_json_hash"] = _artifact_hash(row)
        evidence_rows.append(row)
    payload = {
        "target": target,
        "generated_at": time.time(),
        "layer": 5,
        "name": "Confidence Scoring and Evidence Engine",
        "formula": "evidence_strength*0.4 + reproducibility*0.3 + impact_estimate*0.3",
        "summary": confirmation.get("summary", {}),
        "deduplication": confirmation.get("deduplication", {}),
        "evidence_items": evidence_rows,
        "suppressed_noise": confirmation.get("suppressed_noise", []),
        "needs_more_signal": confirmation.get("needs_more_signal", []),
        "safety": {"new_requests_sent": False, "state_change": False, "notes": "Layer 5 scores already collected evidence only."},
    }
    return payload


def write_evidence_reports(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "evidence-scoring.json", payload)
    checkpoint = {"checkpoint": 5, "name": "Confidence Scoring and Evidence Engine", "status": "completed", "target": target, "summary": payload.get("summary", {}), "reports": {"json": str(out_dir / "evidence-scoring.json"), "markdown": str(out_dir / "evidence-scoring.md")}, "generated_at": time.time()}
    write_json(out_dir / "checkpoint-5.json", checkpoint)
    lines = ["# CAI Checkpoint 5 — Evidence Scoring", "", f"Target: `{target}`", f"Formula: `{payload.get('formula')}`", f"Dedup ratio: `{payload.get('deduplication', {}).get('dedup_ratio', '0 -> 0')}`", "", "## Summary", "```json", json.dumps(payload.get("summary", {}), indent=2, ensure_ascii=False), "```", "", "## Evidence Items"]
    for row in payload.get("evidence_items", [])[:150]:
        lines.append(f"- class=`{row.get('classification')}` confidence=`{row.get('confidence')}` score=`{row.get('confidence_score')}` type=`{row.get('vulnerability_type')}` where=`{row.get('where_found')}` hash=`{row.get('evidence_json_hash')}`")
    write_markdown(out_dir / "evidence-scoring.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI Layer 5 evidence scoring")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    payload = build_evidence_layer(args.target)
    print(json.dumps(write_evidence_reports(args.target, payload), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
