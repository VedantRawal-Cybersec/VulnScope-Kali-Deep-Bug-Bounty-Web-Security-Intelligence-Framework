#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from cai_actuator_registry import ACTUATORS, write_catalog
from cai_agentic_memory import ingest_scan_outputs, record_event, write_memory_report
from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import cai_output_dir, normalize_target

GOAL_PROMPT = """
Persona: Autonomous Security AI.
Primary purpose: find evidence-backed security findings on authorized targets using zero-impact techniques.
Safety guidelines: read-only/passive-first, scope locked, no production data modification, no credential attacks, no exploit execution, stop on unsafe signals.
Autonomy loop: plan, act through typed actuators, observe outputs, update memory, decide next safe step.
""".strip()

DEFAULT_PLAN = [
    "dependency_status",
    "target_profile",
    "passive_recon",
    "input_inventory",
    "hypothesis_matrix",
    "evidence_review",
    "evidence_scoring",
    "prioritize",
    "report",
    "learning",
    "adaptive_risk",
    "business_review",
    "feedback",
]


def _checkpoint_exists(target: str, actuator: str) -> bool:
    out = cai_output_dir(target)
    mapping = {
        "target_profile": out / "checkpoint-0.json",
        "passive_recon": out / "checkpoint-1.json",
        "input_inventory": out / "checkpoint-2.json",
        "hypothesis_matrix": out / "checkpoint-3.json",
        "evidence_review": out / "checkpoint-4.json",
        "evidence_scoring": out / "checkpoint-5.json",
        "prioritize": out / "checkpoint-6.json",
        "report": out / "checkpoint-7.json",
        "learning": out / "checkpoint-learning.json",
        "adaptive_risk": out / "checkpoint-adaptive-risk.json",
        "business_review": out / "checkpoint-business-workflow.json",
        "feedback": out / "checkpoint-feedback.json",
    }
    if actuator == "dependency_status":
        return Path("reports/output/cai-superior/dependencies/checkpoint-dependencies.json").exists()
    return mapping.get(actuator, Path("__missing__")).exists()


def build_plan(target: str, *, include_subdomains: bool = False, criticality: str = "normal", force: bool = False) -> dict[str, Any]:
    target = normalize_target(target)
    steps = []
    for index, actuator in enumerate(DEFAULT_PLAN, 1):
        exists = _checkpoint_exists(target, actuator)
        steps.append({
            "order": index,
            "actuator": actuator,
            "description": ACTUATORS[actuator].description,
            "status": "pending" if force or not exists else "already_completed",
            "parameters": {"target": target, "include_subdomains": include_subdomains, "criticality": criticality},
            "safety": {"safe": ACTUATORS[actuator].safe, "writes_target_data": ACTUATORS[actuator].writes_target_data, "requires_human_approval": ACTUATORS[actuator].requires_human_approval},
        })
    return {
        "target": target,
        "generated_at": time.time(),
        "brain_provider": os.getenv("CAI_BRAIN_PROVIDER", "deterministic-local-planner"),
        "goal_prompt": GOAL_PROMPT,
        "autonomy_components": {
            "brain": "deterministic local planning layer with optional external LLM provider metadata",
            "actuators": "typed safe function registry",
            "memory": "SQLite short-term and long-term memory store",
            "sensors": "user command, schedule, webhook, file-change trigger descriptors",
        },
        "steps": steps,
        "decision": {
            "next_pending": next((s["actuator"] for s in steps if s["status"] == "pending"), "none"),
            "completion_ratio": f"{len([s for s in steps if s['status'] == 'already_completed'])}/{len(steps)}",
        },
    }


def observe(target: str) -> dict[str, Any]:
    target = normalize_target(target)
    memory_payload = ingest_scan_outputs(target)
    write_memory_report(target, memory_payload)
    out = cai_output_dir(target)
    summary_path = out / "cai-superior-summary.json"
    summary: dict[str, Any] = {}
    try:
        if summary_path.exists():
            summary = json.loads(summary_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        summary = handled_error(component="brain", action="read_summary", error=exc)
    event = record_event(target, "brain_observation", {"summary": summary.get("status", "unknown"), "memory": memory_payload.get("summary", {})})
    return {"target": target, "generated_at": time.time(), "memory": memory_payload, "event": event, "summary": summary}


def write_plan(target: str, plan: dict[str, Any]) -> dict[str, Any]:
    out = cai_output_dir(target)
    write_catalog()
    write_json(out / "agentic-plan.json", plan)
    checkpoint = {"checkpoint": "agentic-brain", "name": "Agentic Brain Planner", "status": "completed", "target": target, "summary": plan.get("decision", {}), "reports": {"json": str(out / "agentic-plan.json"), "markdown": str(out / "agentic-plan.md")}, "generated_at": time.time()}
    write_json(out / "checkpoint-agentic-brain.json", checkpoint)
    lines = ["# CAI Agentic Brain Plan", "", f"Target: `{target}`", f"Brain provider: `{plan.get('brain_provider')}`", "", "## Decision", "```json", json.dumps(plan.get("decision", {}), indent=2, ensure_ascii=False), "```", "", "## Steps"]
    for step in plan.get("steps", []):
        lines.append(f"- `{step.get('order')}` actuator=`{step.get('actuator')}` status=`{step.get('status')}` desc={step.get('description')}")
    write_markdown(out / "agentic-plan.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI agentic brain planner")
    parser.add_argument("--target", required=True)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", default="normal", choices=["low", "normal", "high", "critical"])
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--observe", action="store_true")
    args = parser.parse_args()
    payload = observe(args.target) if args.observe else build_plan(args.target, include_subdomains=args.include_subdomains, criticality=args.criticality, force=args.force)
    if not args.observe:
        write_plan(args.target, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
