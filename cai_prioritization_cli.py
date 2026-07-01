#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from typing import Any

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target

PRIORITY_WEIGHT = {
    "CONFIRMED": 100,
    "REVIEW LEAD": 55,
    "NOISE": 0,
}
TYPE_WEIGHT = {
    "IDOR/BOLA": 35,
    "SQLi": 35,
    "SSRF": 30,
    "Open Redirect": 20,
    "CORS": 20,
    "Auth/JWT": 30,
    "Safe Parameter Review": 12,
    "Header Hardening": 6,
}


def _load_evidence(target: str) -> dict[str, Any]:
    path = cai_output_dir(target) / "evidence-scoring.json"
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return {"evidence_items": [], "load_error": handled_error(component="prioritization", action="load_evidence", error=exc, fallback_used="empty_evidence")}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _cluster_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (_norm(row.get("vulnerability_type") or row.get("type")), _norm(row.get("url_path") or row.get("path")), _norm(row.get("parameter")))


def _priority(row: dict[str, Any]) -> float:
    base = PRIORITY_WEIGHT.get(str(row.get("classification") or "").upper(), 20)
    t = TYPE_WEIGHT.get(str(row.get("vulnerability_type") or row.get("type") or ""), 10)
    score = float(row.get("confidence_score") or 0.0)
    return round(base + t + (score * 20), 3)


def build_prioritization(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    data = _load_evidence(target)
    rows = [r for r in data.get("evidence_items", []) or [] if isinstance(r, dict)]
    clusters: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        clusters[_cluster_key(row)].append(row)
    out: list[dict[str, Any]] = []
    for key, items in clusters.items():
        ranked = sorted(items, key=_priority, reverse=True)
        representative = dict(ranked[0])
        representative["cluster_key"] = {"type": key[0], "path": key[1], "parameter": key[2]}
        representative["cluster_size"] = len(items)
        representative["priority_score"] = _priority(representative)
        representative["duplicate_hashes"] = [x.get("evidence_json_hash") for x in ranked[1:] if x.get("evidence_json_hash")]
        out.append(representative)
    out.sort(key=lambda r: r.get("priority_score", 0), reverse=True)
    return {
        "target": target,
        "generated_at": time.time(),
        "layer": 6,
        "name": "Deduplication and Prioritization Agent",
        "summary": {
            "input_items": len(rows),
            "clusters": len(out),
            "duplicates_removed": max(0, len(rows) - len(out)),
            "confirmed_clusters": len([x for x in out if x.get("classification") == "CONFIRMED"]),
            "review_lead_clusters": len([x for x in out if x.get("classification") == "REVIEW LEAD"]),
        },
        "prioritized_items": out,
        "safety": {"new_requests_sent": False, "state_change": False, "notes": "Layer 6 groups and ranks existing scored evidence only."},
    }


def write_prioritization_reports(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "prioritized-findings.json", payload)
    checkpoint = {"checkpoint": 6, "name": "Deduplication and Prioritization Agent", "status": "completed", "target": target, "summary": payload.get("summary", {}), "reports": {"json": str(out_dir / "prioritized-findings.json"), "markdown": str(out_dir / "prioritized-findings.md")}, "generated_at": time.time()}
    write_json(out_dir / "checkpoint-6.json", checkpoint)
    lines = ["# CAI Checkpoint 6 — Deduplicated Priorities", "", f"Target: `{target}`", "", "## Summary", "```json", json.dumps(payload.get("summary", {}), indent=2, ensure_ascii=False), "```", "", "## Prioritized Items"]
    for row in payload.get("prioritized_items", [])[:150]:
        lines.append(f"- priority=`{row.get('priority_score')}` class=`{row.get('classification')}` confidence=`{row.get('confidence')}` type=`{row.get('vulnerability_type')}` where=`{row.get('where_found')}` cluster_size=`{row.get('cluster_size')}`")
    write_markdown(out_dir / "prioritized-findings.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI Layer 6 prioritization")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    payload = build_prioritization(args.target)
    print(json.dumps(write_prioritization_reports(args.target, payload), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
