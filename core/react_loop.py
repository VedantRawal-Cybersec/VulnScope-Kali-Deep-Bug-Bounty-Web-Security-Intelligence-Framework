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

from core.live_dashboard import LiveDashboard, target_components
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

ACTION_LABELS = {
    "dependency_status": "Dependency readiness",
    "target_profile": "Target profile",
    "passive_recon": "Passive reconnaissance",
    "input_inventory": "Input inventory",
    "hypothesis_matrix": "Hypothesis matrix",
    "evidence_review": "Evidence review",
    "evidence_scoring": "Evidence scoring",
    "prioritize": "Finding prioritization",
    "report": "Report generation",
    "learning": "Learning notes",
    "adaptive_risk": "Adaptive risk review",
    "business_review": "Business logic review",
    "feedback": "Feedback checkpoint",
}


def _action_label(action: str) -> str:
    return ACTION_LABELS.get(action, action.replace("_", " ").title())


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


def _decision_summary(decision: dict[str, Any]) -> str:
    for key in ("next_action", "analysis", "reason_to_continue", "risk"):
        value = decision.get(key)
        if value:
            return str(value)
    return "Safe autonomous step selected by Ollama/fallback planner"


def _observation_evidence(observation: dict[str, Any]) -> str:
    result = observation.get("result") or observation.get("gate") or observation
    if isinstance(result, dict):
        summary = result.get("summary") or result.get("status") or result.get("name") or result
        return json.dumps(summary, ensure_ascii=False, default=str)[:600]
    return str(result)[:600]


def _confirmation_status(observation: dict[str, Any]) -> str:
    blob = json.dumps(observation, ensure_ascii=False, default=str).lower()
    if "unconfirmed" in blob or "not_confirmed" in blob:
        return "review_lead"
    if '"confirmed"' in blob or 'confirmed": true' in blob or "status=confirmed" in blob:
        return "confirmed"
    return "review_lead"


def _severity_from_observation(observation: dict[str, Any]) -> str:
    blob = json.dumps(observation, ensure_ascii=False, default=str).lower()
    if "critical" in blob:
        return "CRITICAL"
    if "high" in blob or "high_confidence" in blob or "high confidence" in blob:
        return "HIGH"
    if "medium" in blob:
        return "MEDIUM"
    if "low" in blob:
        return "LOW"
    return "INFO"


def _confidence_from_observation(observation: dict[str, Any]) -> str:
    blob = json.dumps(observation, ensure_ascii=False, default=str).lower()
    if "high_confidence" in blob or "high confidence" in blob:
        return "High evidence confidence"
    if _confirmation_status(observation) == "confirmed":
        return "Confirmed by evidence engine"
    return "Review required"


def _validation_steps(target: str, action: str) -> str:
    label = _action_label(action)
    return "\n".join([
        f"1. Open the generated {label} artifact for {target}.",
        "2. Review the evidence snippet, affected URL/path, parameter inventory, and confidence notes.",
        "3. Validate manually only inside the authorized scope using read-only or zero-impact checks.",
        "4. Use cli-final-dashboard.md and detailed-findings.json for the report package.",
    ])


def _progress(turn: int, max_turns: int) -> int:
    if max_turns <= 0:
        return 0
    return int(max(0, min(100, (turn / max_turns) * 100)))


def run_loop(
    target: str,
    initial_scan_output: str = "",
    *,
    max_turns: int = 15,
    include_subdomains: bool = False,
    criticality: str = "normal",
    force: bool = False,
    live_dashboard: bool = False,
    final_dashboard: bool = True,
) -> dict[str, Any]:
    """Run a safe ReAct loop: think, call one allowlisted actuator, observe, repeat."""
    target = normalize_target(target)
    target_parts = target_components(target)
    state = StateManager(target)
    dashboard = LiveDashboard(target, max_turns=max_turns, enabled=final_dashboard, live_stream=live_dashboard)
    dashboard.start()
    dashboard.event("INFO", "Scope locked to authorized target. Zero-impact mode active.")

    if force:
        state.state["completed"] = []
        state.state["stopped"] = False
        state.state["stop_reason"] = ""
        state.save()
        dashboard.event("INFO", "Previous ReAct checkpoint cleared because --force was provided.")

    current_output = initial_scan_output or "Loop started. No prior output."
    executed: list[dict[str, Any]] = []
    interrupted = False

    try:
        for turn in range(1, max_turns + 1):
            state.state["turn"] = turn
            completed = list(state.state.get("completed", []))
            dashboard.update(
                phase="AI Planning",
                phase_progress=_progress(turn - 1, max_turns),
                turn=turn,
                requests=len(executed),
                findings=dashboard.finding_count(),
                action=f"Ollama selecting next safe actuator ({turn}/{max_turns})",
                probe_string="safe-planning:allowlisted-actuator-only",
                hypothesis="Waiting for Ollama/fallback planner decision",
                evidence=current_output[:600],
                safety_status="Allowlisted actuators only • GET/safe topics • no production data modification",
            )

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
                dashboard.update(
                    phase="Stopping",
                    phase_progress=_progress(turn, max_turns),
                    action="Planner selected stop",
                    probe_string=f"safe-actuator:{action}",
                    hypothesis=_decision_summary(decision),
                    safety_status="Stopped before actuator execution",
                )
                dashboard.event("INFO", decision.get("reason_to_continue") or "Planner selected stop.")
                state.stop(decision.get("reason_to_continue") or "brain selected stop")
                break

            if action in completed:
                remaining = [x for x in DEFAULT_PLAN if x not in completed]
                action = remaining[0] if remaining else "stop"
                if action == "stop":
                    dashboard.update(phase="Complete", phase_progress=100, action="All safe actuators completed", probe_string="safe-actuator:stop")
                    dashboard.event("SUCCESS", "All safe actuators completed.")
                    state.stop("all safe actuators completed")
                    break

            label = _action_label(action)
            dashboard.update(
                phase=label,
                phase_progress=_progress(turn - 1, max_turns),
                action=f"Selected actuator: {label}",
                probe_string=f"safe-actuator:{action}",
                hypothesis=_decision_summary(decision),
                safety_status="Checking scope gate before execution",
            )
            dashboard.event("THINKING", f"Turn {turn}: selected {label}.")

            gate = evaluate_action(target=target, candidate_url=target, method="GET", topic=action, include_subdomains=include_subdomains, user_approved=False)
            if not gate.get("allowed"):
                observation = {"action": action, "status": "blocked_by_safety_gate", "gate": gate}
                state.mark_completed(action, observation)
                executed.append(observation)
                current_output = _scan_output_from_result(observation)
                dashboard.update(
                    phase=label,
                    phase_progress=_progress(turn, max_turns),
                    requests=len(executed),
                    findings=dashboard.finding_count(),
                    action=f"Blocked by safety gate: {label}",
                    evidence=_observation_evidence(observation),
                    safety_status="Blocked by scope/safety gate",
                )
                dashboard.event("BLOCKED", f"{label} blocked by safety gate.")
                continue

            dashboard.update(
                phase=label,
                phase_progress=_progress(turn - 1, max_turns),
                action=f"Running {label}",
                safety_status="Allowed by safety gate • zero-impact execution",
                requests=len(executed) + 1,
            )
            try:
                raw_result = call_actuator(action, target=target, include_subdomains=include_subdomains, criticality=criticality)
                observation = {"action": action, "status": "completed", "gate": gate, "result": _summarize_result(raw_result)}
                dashboard.event("SUCCESS", f"{label} completed.")
            except Exception as exc:
                observation = {"action": action, "status": "handled_error", "error": handled_error(component="react_loop", action=action, error=exc)}
                dashboard.event("WARNING", f"{label} handled error and continued safely.")

            state.mark_completed(action, observation)
            executed.append(observation)
            if _is_reportable_observation(observation):
                state.add_finding({"turn": turn, "action": action, "observation": observation})
                evidence = _observation_evidence(observation)
                confirmation = _confirmation_status(observation)
                dashboard.add_finding(
                    f"{label} Evidence Lead",
                    f"{label} produced {confirmation.replace('_', ' ')} evidence that must be reviewed before external reporting.",
                    _severity_from_observation(observation),
                    url=target,
                    parameter=target_parts.get("parameters", "—"),
                    test_string=f"safe-actuator:{action}",
                    evidence=evidence,
                    cvss="Pending CVSS scoring" if confirmation != "confirmed" else "Evidence-scored by confirmation engine",
                    confidence=_confidence_from_observation(observation),
                    reproduction=_validation_steps(target, action),
                    confirmation=confirmation,
                )
                dashboard.event("FINDING", f"Detailed result captured from {label}.")

            current_output = _scan_output_from_result(observation)
            dashboard.update(
                phase=label,
                phase_progress=_progress(turn, max_turns),
                requests=len(executed),
                findings=dashboard.finding_count(),
                action=f"Observed result from {label}",
                evidence=_observation_evidence(observation),
                safety_status="Observation recorded • state checkpoint updated",
            )
        else:
            state.stop("max turns reached")
            dashboard.event("INFO", "Max turns reached; finalizing reports.")
    except KeyboardInterrupt:
        interrupted = True
        state.stop("interrupted by user")
        dashboard.event("WARNING", "Interrupted by user; final CLI dashboard and reports are being written.")
    finally:
        dashboard.update(
            phase="Final Dashboard",
            phase_progress=100,
            action="Writing final ReAct reports",
            findings=dashboard.finding_count(),
            requests=len(executed),
            safety_status="Finalized without production data modification",
        )
        dashboard.stop(final=False)

    checkpoint = state.write_report()
    out = cai_output_dir(target)
    dashboard_reports = dashboard.write_reports(out)
    payload = {
        "target": target,
        "generated_at": time.time(),
        "mode": "safe_react_loop",
        "max_turns": max_turns,
        "interrupted": interrupted,
        "executed": executed,
        "state_checkpoint": checkpoint,
        "final_state": state.state,
        "reports": {
            "react_run_json": str(out / "react-run.json"),
            "react_run_md": str(out / "react-run.md"),
            "react_state_md": str(out / "react-state.md"),
            **dashboard_reports,
        },
        "safety": {
            "allowlisted_actuators_only": True,
            "shell_execution": False,
            "target_data_modification": False,
            "scope_gate_per_turn": True,
            "kali_cli_dashboard_only": True,
            "website_dashboard": False,
            "final_dashboard_direct_stdout": True,
        },
    }
    write_json(out / "react-run.json", payload)
    lines = [
        "# VulnScope Safe ReAct Loop",
        "",
        f"Target: `{target}`",
        f"Executed turns: `{len(executed)}`",
        f"Interrupted: `{interrupted}`",
        f"Stopped: `{state.state.get('stopped', False)}`",
        f"Stop reason: `{state.state.get('stop_reason', '')}`",
        "",
        "## Reports",
    ]
    for name, path in payload["reports"].items():
        lines.append(f"- `{name}`: `{path}`")
    lines += ["", "## Turns"]
    for item in executed:
        lines.append(f"- action=`{item.get('action')}` status=`{item.get('status')}` result=`{json.dumps(item.get('result', item.get('gate', {})), ensure_ascii=False)[:500]}`")
    write_markdown(out / "react-run.md", lines)
    dashboard.report_paths = dict(payload["reports"])
    if final_dashboard:
        dashboard.show_final()
        final_md = out / "cli-final-dashboard.md"
        final_md.write_text("# VulnScope Ultimate Kali CLI Final Dashboard\n\n```text\n" + dashboard.final_text(color=False) + "\n```\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope safe ReAct loop")
    parser.add_argument("--target", required=True)
    parser.add_argument("--max-turns", type=int, default=15)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", default="normal", choices=["low", "normal", "high", "critical"])
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--live-dashboard", action="store_true", default=False, help="Optional live terminal refresh during execution. Final CLI dashboard is shown by default.")
    parser.add_argument("--no-live-dashboard", action="store_true", help="Compatibility flag. Live refresh is already off by default.")
    parser.add_argument("--no-final-dashboard", action="store_true")
    args = parser.parse_args()
    payload = run_loop(
        args.target,
        max_turns=args.max_turns,
        include_subdomains=args.include_subdomains,
        criticality=args.criticality,
        force=args.force,
        live_dashboard=bool(args.live_dashboard and not args.no_live_dashboard),
        final_dashboard=not args.no_final_dashboard,
    )
    print(json.dumps({"status": "completed", "reports": payload.get("reports", {})}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
