#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, host_from_target, normalize_target
from cai_learning_cli import DB_PATH, _connect

VALID_FEEDBACK = {"accepted", "rejected", "duplicate", "needs_more_info", "unreviewed"}


def record_feedback(target: str, item_hash: str, feedback: str) -> dict[str, Any]:
    target = normalize_target(target)
    host = host_from_target(target)
    feedback = feedback if feedback in VALID_FEEDBACK else "unreviewed"
    conn = _connect()
    conn.execute("INSERT INTO review_outcomes VALUES (?, ?, ?, ?, ?, ?)", (host, item_hash, "external_feedback", 0.0, feedback, time.time()))
    conn.commit()
    rows = conn.execute("SELECT feedback, COUNT(*) FROM review_outcomes GROUP BY feedback").fetchall()
    conn.close()
    return {"target": target, "database": str(DB_PATH), "recorded": {"item_hash": item_hash, "feedback": feedback}, "feedback_counts": {k: v for k, v in rows}, "generated_at": time.time()}


def calibration_summary(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    host = host_from_target(target)
    conn = _connect()
    rows = conn.execute("SELECT feedback, COUNT(*) FROM review_outcomes WHERE host=? GROUP BY feedback", (host,)).fetchall()
    total = sum(v for _, v in rows)
    accepted = sum(v for k, v in rows if k == "accepted")
    rejected = sum(v for k, v in rows if k == "rejected")
    conn.close()
    precision_hint = round(accepted / max(1, accepted + rejected), 3)
    return {"target": target, "database": str(DB_PATH), "summary": {"total_feedback": total, "feedback_counts": {k: v for k, v in rows}, "precision_hint": precision_hint}, "generated_at": time.time()}


def write_feedback_reports(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "feedback-calibration.json", payload)
    checkpoint = {"checkpoint": "advanced-feedback", "name": "Continuous Feedback Calibration", "status": "completed", "target": target, "summary": payload.get("summary", payload.get("recorded", {})), "reports": {"json": str(out_dir / "feedback-calibration.json"), "markdown": str(out_dir / "feedback-calibration.md")}, "generated_at": time.time()}
    write_json(out_dir / "checkpoint-feedback.json", checkpoint)
    lines = ["# CAI Advanced Feature — Feedback Calibration", "", f"Target: `{target}`", f"Database: `{payload.get('database')}`", "", "```json", json.dumps(payload, indent=2, ensure_ascii=False), "```"]
    write_markdown(out_dir / "feedback-calibration.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI feedback calibration")
    parser.add_argument("--target", required=True)
    parser.add_argument("--item-hash", default="")
    parser.add_argument("--feedback", default="unreviewed", choices=sorted(VALID_FEEDBACK))
    args = parser.parse_args()
    payload = record_feedback(args.target, args.item_hash, args.feedback) if args.item_hash else calibration_summary(args.target)
    print(json.dumps(write_feedback_reports(args.target, payload), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
