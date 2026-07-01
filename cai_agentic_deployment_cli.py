#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from typing import Any

from cai_actuator_registry import call_actuator, write_catalog
from cai_agentic_memory import ingest_scan_outputs, record_event, write_memory_report
from cai_brain_cli import build_plan, observe, write_plan
from cai_error_handler import handled_error, write_json, write_log, write_markdown
from cai_safety_gate import evaluate_action
from cai_scope_guard import cai_output_dir, normalize_target
from cai_sensors_cli import record_sensor_event, sensor_config, write_sensor_config

BANNER = r"""
╔════════════════════════════════════════════════════════════════════╗
║          CAI AGENTIC DEPLOYMENT — BRAIN / TOOLS / MEMORY          ║
║       Execute → Observe → Decide → Record → Continue Safely        ║
╚════════════════════════════════════════════════════════════════════╝
"""


def _execute_step(step: dict[str, Any], *, target: str, include_subdomains: bool, criticality: str) -> dict[str, Any]:
    actuator = str(step.get("actuator") or "")
    gate = evaluate_action(target=target, candidate_url=target, method="GET", topic=actuator, include_subdomains=include_subdomains, user_approved=False)
    if not gate.get("allowed"):
        return {"actuator": actuator, "status": "blocked_by_safety_gate", "gate": gate}
    result = call_actuator(actuator, target=target, include_subdomains=include_subdomains, criticality=criticality)
    return {"actuator": actuator, "status": "completed", "gate": gate, "result_summary": _summarize_result(result)}


def _summarize_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"type": type(result).__name__}
    if "checkpoint" in result and isinstance(result["checkpoint"], dict):
        return {"checkpoint": result["checkpoint"].get("checkpoint"), "status": result["checkpoint"].get("status"), "summary": result["checkpoint"].get("summary", {})}
    return {"status": result.get("status", "ok"), "keys": sorted(result.keys())[:20], "summary": result.get("summary", {})}


def run_agentic_deployment(target: str, *, include_subdomains: bool = False, criticality: str = "normal", max_iterations: int = 20, force: bool = False) -> dict[str, Any]:
    target = normalize_target(target)
    out = cai_output_dir(target)
    print(BANNER, flush=True)
    print(f"[agentic] target={target}", flush=True)

    sensor_payload = sensor_config(target)
    sensor_checkpoint = write_sensor_config(target, sensor_payload)
    record_sensor_event(target, "user_command", {"mode": "agentic_deployment", "include_subdomains": include_subdomains, "criticality": criticality})
    write_catalog()

    plan = build_plan(target, include_subdomains=include_subdomains, criticality=criticality, force=force)
    write_plan(target, plan)
    record_event(target, "brain_plan_created", {"decision": plan.get("decision", {}), "steps": len(plan.get("steps", []))})

    executed: list[dict[str, Any]] = []
    iterations = 0
    for step in plan.get("steps", []):
        if iterations >= max_iterations:
            executed.append({"actuator": step.get("actuator"), "status": "max_iterations_reached"})
            break
        if step.get("status") != "pending":
            executed.append({"actuator": step.get("actuator"), "status": "skipped_already_completed"})
            continue
        iterations += 1
        print(f"[agentic] execute {iterations}: {step.get('actuator')}", flush=True)
        try:
            outcome = _execute_step(step, target=target, include_subdomains=include_subdomains, criticality=criticality)
        except Exception as exc:
            outcome = {"actuator": step.get("actuator"), "status": "handled_error", "error": handled_error(component="agentic_deployment", action=str(step.get("actuator")), error=exc)}
        executed.append(outcome)
        record_event(target, "actuator_outcome", outcome)
        obs = observe(target)
        record_event(target, "feedback_loop_observation", {"actuator": step.get("actuator"), "memory": obs.get("memory", {}).get("summary", {})})

    memory_payload = ingest_scan_outputs(target)
    memory_checkpoint = write_memory_report(target, memory_payload)
    final_plan = build_plan(target, include_subdomains=include_subdomains, criticality=criticality, force=False)
    write_plan(target, final_plan)

    payload = {
        "target": target,
        "generated_at": time.time(),
        "mode": "agentic_deployment",
        "iterations": iterations,
        "sensor_checkpoint": sensor_checkpoint,
        "memory_checkpoint": memory_checkpoint,
        "executed": executed,
        "final_decision": final_plan.get("decision", {}),
        "reports": {
            "agentic_run_json": str(out / "agentic-run.json"),
            "agentic_run_md": str(out / "agentic-run.md"),
            "agentic_plan_md": str(out / "agentic-plan.md"),
            "agentic_memory_md": str(out / "agentic-memory.md"),
            "agentic_sensors_md": str(out / "agentic-sensors.md"),
            "cai_summary_md": str(out / "cai-superior-summary.md"),
        },
        "safety": {
            "target_data_modification": False,
            "unsafe_methods": False,
            "credential_attacks": False,
            "exploit_execution": False,
            "scope_gate_applied_per_actuator": True,
        },
    }
    write_json(out / "agentic-run.json", payload)
    lines = ["# CAI Agentic Deployment Run", "", f"Target: `{target}`", f"Iterations: `{iterations}`", "", "## Final Decision", "```json", json.dumps(payload.get("final_decision", {}), indent=2, ensure_ascii=False), "```", "", "## Executed Steps"]
    for row in executed:
        lines.append(f"- actuator=`{row.get('actuator')}` status=`{row.get('status')}` summary=`{json.dumps(row.get('result_summary', row.get('gate', {})), ensure_ascii=False)[:500]}`")
    write_markdown(out / "agentic-run.md", lines)
    write_log(f"agentic deployment completed target={target} iterations={iterations}")
    print(json.dumps(payload.get("reports", {}), indent=2), flush=True)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI agentic deployment loop")
    parser.add_argument("--target", required=True)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", default="normal", choices=["low", "normal", "high", "critical"])
    parser.add_argument("--max-iterations", type=int, default=20)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    payload = run_agentic_deployment(args.target, include_subdomains=args.include_subdomains, criticality=args.criticality, max_iterations=args.max_iterations, force=args.force)
    print(json.dumps({"status": "completed", "reports": payload.get("reports", {})}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
