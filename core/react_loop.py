#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from typing import Any

from cai_actuator_registry import call_actuator
from cai_error_handler import handled_error, write_json, write_markdown
from cai_safety_gate import evaluate_action
from cai_scope_guard import cai_output_dir, normalize_target

from core.ollama_brain import ALLOWED_ACTIONS, think
from core.state_manager import StateManager

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


def _summarize_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"type": type(result).__name__, "text": str(result)[:600]}
    checkpoint = result.get("checkpoint")
    if isinstance(checkpoint, dict):
        return {
            "status": checkpoint.get("status", "completed"),
            "checkpoint": checkpoint.get("checkpoint"),
            "name": checkpoint.get("name"),
            "summary": checkpoint.get("summary", {}),
        }
    return {"status": result.get("status", "completed"), "summary": result.get("summary", {}), "keys": sorted(result.keys())[:20]}


def _scan_output_from_result(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, ensure_ascii=False, default=str)[:5000]


def _is_reportable_observation(observation: dict[str, Any]) -> bool:
    blob = json.dumps(observation, ensure_ascii=False, default=str).lower()
    return any(marker in blob for marker in ["confirmed", "high_confidence", "high confidence", "surface_count", "review_leads"])


def run_loop(
    target: str,
    initial_scan_output: str = "",
    *,
    max_turns: int = 15,
    include_subdomains: bool = False,
    criticality: str = "normal",
    force: bool = False,
) -> dict[str, Any]:
    """Run a safe ReAct loop: think, call one allowlisted actuator, observe, repeat."""
    target = normalize_target(target)
    state = StateManager(target)
    if force:
        state.state["completed"] = []
        state.state["stopped"] = False
        state.state["stop_reason"] = ""
        state.save()

    current_output = initial_scan_output or "Loop started. No prior output."
    executed: list[dict[str, Any]] = []

    for turn in range(1, max_turns + 1):
        state.state["turn"] = turn
        completed = list(state.state.get("completed", []))
        context = {
            "target": target,
            "phase": "safe_react",
            "turn": turn,
            "plan": DEFAULT_PLAN,
            "completed": completed,
            "findings": state.state.get("findings", []),
        }
        decision = think(current_output, context)
        state.decision(decision)
        action = str(decision.get("action") or "stop")

        if action == "stop" or action not in ALLOWED_ACTIONS:
            state.stop(decision.get("reason_to_continue") or "brain selected stop")
            break
        if action in completed:
            remaining = [x for x in DEFAULT_PLAN if x not in completed]
            action = remaining[0] if remaining else "stop"
            if action == "stop":
                state.stop("all safe actuators completed")
                break

        gate = evaluate_action(target=target, candidate_url=target, method="GET", topic=action, include_subdomains=include_subdomains, user_approved=False)
        if not gate.get("allowed"):
            observation = {"action": action, "status": "blocked_by_safety_gate", "gate": gate}
            state.mark_completed(action, observation)
            executed.append(observation)
            current_output = _scan_output_from_result(observation)
            continue

        try:
            raw_result = call_actuator(action, target=target, include_subdomains=include_subdomains, criticality=criticality)
            observation = {"action": action, "status": "completed", "gate": gate, "result": _summarize_result(raw_result)}
        except Exception as exc:
            observation = {"action": action, "status": "handled_error", "error": handled_error(component="react_loop", action=action, error=exc)}

        state.mark_completed(action, observation)
        executed.append(observation)
        if _is_reportable_observation(observation):
            state.add_finding({"turn": turn, "action": action, "observation": observation})
        current_output = _scan_output_from_result(observation)

    else:
        state.stop("max turns reached")

    checkpoint = state.write_report()
    out = cai_output_dir(target)
    payload = {
        "target": target,
        "generated_at": time.time(),
        "mode": "safe_react_loop",
        "max_turns": max_turns,
        "executed": executed,
        "state_checkpoint": checkpoint,
        "final_state": state.state,
        "reports": {
            "react_run_json": str(out / "react-run.json"),
            "react_run_md": str(out / "react-run.md"),
            "react_state_md": str(out / "react-state.md"),
        },
        "safety": {
            "allowlisted_actuators_only": True,
            "shell_execution": False,
            "target_data_modification": False,
            "scope_gate_per_turn": True,
        },
    }
    write_json(out / "react-run.json", payload)
    lines = [
        "# VulnScope Safe ReAct Loop",
        "",
        f"Target: `{target}`",
        f"Executed turns: `{len(executed)}`",
        f"Stopped: `{state.state.get('stopped', False)}`",
        f"Stop reason: `{state.state.get('stop_reason', '')}`",
        "",
        "## Turns",
    ]
    for item in executed:
        lines.append(f"- action=`{item.get('action')}` status=`{item.get('status')}` result=`{json.dumps(item.get('result', item.get('gate', {})), ensure_ascii=False)[:500]}`")
    write_markdown(out / "react-run.md", lines)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope safe ReAct loop")
    parser.add_argument("--target", required=True)
    parser.add_argument("--max-turns", type=int, default=15)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", default="normal", choices=["low", "normal", "high", "critical"])
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    payload = run_loop(args.target, max_turns=args.max_turns, include_subdomains=args.include_subdomains, criticality=args.criticality, force=args.force)
    print(json.dumps({"status": "completed", "reports": payload.get("reports", {})}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
