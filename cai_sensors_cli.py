#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from cai_error_handler import write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target

SENSOR_TYPES = {
    "user_command": "Operator starts a run from CLI or main workflow.",
    "scheduled_timer": "Recurring local scheduler or CI job starts a safe run.",
    "webhook": "CI/CD or repository webhook drops a trigger file for review.",
    "file_change": "New code/endpoints file is detected and queued for passive analysis.",
}


def _hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


def sensor_config(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    return {
        "target": target,
        "generated_at": time.time(),
        "sensors": [{"type": key, "description": desc, "enabled": key == "user_command", "safety": "scope guard required before actuator execution"} for key, desc in SENSOR_TYPES.items()],
        "trigger_directory": "reports/input/cai-triggers",
        "audit_log": "reports/output/cai-superior/agentic/sensor-events.jsonl",
        "safety": {"target_whitelisting": True, "rate_limit_required": True, "state_change_allowed": False},
    }


def record_sensor_event(target: str, sensor_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    target = normalize_target(target)
    event = {"id": _hash({"target": target, "sensor_type": sensor_type, "payload": payload, "ts": time.time()}), "target": target, "sensor_type": sensor_type, "payload": payload, "created_at": time.time()}
    log = Path("reports/output/cai-superior/agentic/sensor-events.jsonl")
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8", errors="ignore") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event


def write_sensor_config(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    out = cai_output_dir(target)
    write_json(out / "agentic-sensors.json", payload)
    checkpoint = {"checkpoint": "agentic-sensors", "name": "Agentic Sensors", "status": "completed", "target": target, "summary": {"sensors": len(payload.get("sensors", []))}, "reports": {"json": str(out / "agentic-sensors.json"), "markdown": str(out / "agentic-sensors.md")}, "generated_at": time.time()}
    write_json(out / "checkpoint-agentic-sensors.json", checkpoint)
    lines = ["# CAI Agentic Sensors", "", f"Target: `{target}`", "", "## Sensors"]
    for row in payload.get("sensors", []):
        lines.append(f"- `{row.get('type')}` enabled=`{row.get('enabled')}` — {row.get('description')}")
    write_markdown(out / "agentic-sensors.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI agentic sensors")
    parser.add_argument("--target", required=True)
    parser.add_argument("--event", default="")
    parser.add_argument("--payload-json", default="{}")
    args = parser.parse_args()
    if args.event:
        payload = record_sensor_event(args.target, args.event, json.loads(args.payload_json))
    else:
        payload = sensor_config(args.target)
        write_sensor_config(args.target, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
