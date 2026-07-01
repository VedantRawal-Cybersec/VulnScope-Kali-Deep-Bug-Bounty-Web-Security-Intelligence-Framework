#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, host_from_target, normalize_target

DB_PATH = Path("reports/output/cai-superior/cai_learning.db")


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS endpoint_patterns (host TEXT, path_template TEXT, endpoint_class TEXT, input_types TEXT, priority REAL, created_at REAL)")
    conn.execute("CREATE TABLE IF NOT EXISTS review_outcomes (host TEXT, item_hash TEXT, classification TEXT, confidence_score REAL, feedback TEXT, created_at REAL)")
    return conn


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return handled_error(component="learning", action="load_" + path.name, error=exc, fallback_used="empty_source")


def update_learning_db(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    host = host_from_target(target)
    out_dir = cai_output_dir(target)
    inventory = _load(out_dir / "input-inventory.json")
    prioritized = _load(out_dir / "prioritized-findings.json")
    conn = _connect()
    endpoint_rows = 0
    if isinstance(inventory, dict):
        for endpoint in inventory.get("endpoints", []) or []:
            input_types = sorted({str(x.get("inferred_type") or "unknown") for x in endpoint.get("inputs", []) or []})
            conn.execute("INSERT INTO endpoint_patterns VALUES (?, ?, ?, ?, ?, ?)", (host, endpoint.get("path_template"), endpoint.get("endpoint_class"), json.dumps(input_types), 0.0, time.time()))
            endpoint_rows += 1
    outcome_rows = 0
    if isinstance(prioritized, dict):
        for item in prioritized.get("prioritized_items", []) or []:
            item_hash = str(item.get("evidence_json_hash") or item.get("id") or item.get("where_found") or "unknown")
            conn.execute("INSERT INTO review_outcomes VALUES (?, ?, ?, ?, ?, ?)", (host, item_hash, item.get("classification"), float(item.get("confidence_score") or 0.0), "unreviewed", time.time()))
            outcome_rows += 1
    conn.commit()
    total_patterns = conn.execute("SELECT COUNT(*) FROM endpoint_patterns").fetchone()[0]
    total_outcomes = conn.execute("SELECT COUNT(*) FROM review_outcomes").fetchone()[0]
    conn.close()
    return {
        "target": target,
        "generated_at": time.time(),
        "feature": "Autonomous Learning and Knowledge Graph",
        "database": str(DB_PATH),
        "summary": {
            "endpoint_patterns_added": endpoint_rows,
            "review_outcomes_added": outcome_rows,
            "total_endpoint_patterns": total_patterns,
            "total_review_outcomes": total_outcomes,
        },
        "safety": {"new_requests_sent": False, "state_change": False, "notes": "Learning mode stores local metadata only."},
    }


def write_learning_reports(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "learning-graph.json", payload)
    checkpoint = {"checkpoint": "advanced-learning", "name": "Autonomous Learning and Knowledge Graph", "status": "completed", "target": target, "summary": payload.get("summary", {}), "reports": {"json": str(out_dir / "learning-graph.json"), "markdown": str(out_dir / "learning-graph.md")}, "generated_at": time.time()}
    write_json(out_dir / "checkpoint-learning.json", checkpoint)
    lines = ["# CAI Advanced Feature — Learning Graph", "", f"Target: `{target}`", f"Database: `{payload.get('database')}`", "", "## Summary", "```json", json.dumps(payload.get("summary", {}), indent=2, ensure_ascii=False), "```"]
    write_markdown(out_dir / "learning-graph.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI learning graph updater")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    payload = update_learning_db(args.target)
    print(json.dumps(write_learning_reports(args.target, payload), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
