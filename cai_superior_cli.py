#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from typing import Any

from cai_actuator_registry import write_catalog
from cai_adaptive_risk_cli import build_adaptive_risk, write_adaptive_risk_reports
from cai_agentic_memory import ingest_scan_outputs, record_event, write_memory_report
from cai_brain_cli import build_plan, observe, write_plan
from cai_business_logic_cli import build_business_review, write_business_review_reports
from cai_error_handler import handled_error, write_json, write_log, write_markdown
from cai_evidence_engine_cli import build_evidence_layer, write_evidence_reports
from cai_feedback_cli import calibration_summary, write_feedback_reports
from cai_hypothesis_agent_cli import generate_hypotheses, write_hypothesis_reports
from cai_learning_cli import update_learning_db, write_learning_reports
from cai_parameter_analysis_cli import build_inventory, write_inventory_reports
from cai_prioritization_cli import build_prioritization, write_prioritization_reports
from cai_recon_agent_cli import run_recon, write_recon_reports
from cai_report_agent_cli import build_reports, write_report_outputs
from cai_scope_guard import cai_output_dir, normalize_target
from cai_sensors_cli import record_sensor_event, sensor_config, write_sensor_config
from cai_target_profiler_cli import build_target_profile, write_profile_reports
from cai_verification_agent_cli import verify_from_existing_evidence, write_verification_reports

BANNER = r"""
╔════════════════════════════════════════════════════════════════════╗
║                  CAI IMPLEMENTATION — ZERO IMPACT MODE            ║
║      Profile → Recon → Inputs → Matrix → Evidence → Reports       ║
╚════════════════════════════════════════════════════════════════════╝
"""


def build_run_summary(target: str, checkpoints: dict[str, dict[str, Any]]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    return {
        "target": normalize_target(target),
        "generated_at": time.time(),
        "status": "completed",
        "layers_completed": [int(x) for x in sorted([k for k in checkpoints if str(k).isdigit()], key=int)],
        "advanced_completed": sorted([k for k in checkpoints if not str(k).isdigit()]),
        "checkpoints": checkpoints,
        "reports": {
            "summary": str(out_dir / "cai-superior-summary.md"),
            "agentic_plan": str(out_dir / "agentic-plan.md"),
            "agentic_sensors": str(out_dir / "agentic-sensors.md"),
            "agentic_memory": str(out_dir / "agentic-memory.md"),
            "target_profile": str(out_dir / "target-profile.md"),
            "asset_graph": str(out_dir / "asset-graph.md"),
            "input_inventory": str(out_dir / "input-inventory.md"),
            "review_matrix": str(out_dir / "hypothesis-matrix.md"),
            "evidence_review": str(out_dir / "verification-results.md"),
            "evidence_scoring": str(out_dir / "evidence-scoring.md"),
            "priorities": str(out_dir / "prioritized-findings.md"),
            "reports": str(out_dir / "submission-reports.md"),
            "learning": str(out_dir / "learning-graph.md"),
            "adaptive_risk": str(out_dir / "adaptive-risk.md"),
            "business_review": str(out_dir / "business-workflow-review.md"),
            "feedback": str(out_dir / "feedback-calibration.md"),
        },
    }


def write_run_summary(target: str, payload: dict[str, Any]) -> None:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "cai-superior-summary.json", payload)
    lines = [
        "# CAI Implementation Summary",
        "",
        f"Target: `{payload.get('target')}`",
        f"Status: `{payload.get('status')}`",
        f"Layers completed: `{', '.join(str(x) for x in payload.get('layers_completed', []))}`",
        f"Advanced features completed: `{', '.join(str(x) for x in payload.get('advanced_completed', []))}`",
        "",
        "## Checkpoints",
    ]
    for key in sorted(payload.get("checkpoints", {}), key=lambda x: (0, int(x)) if str(x).isdigit() else (1, str(x))):
        cp = payload["checkpoints"][key]
        lines.append(f"- Checkpoint `{key}` `{cp.get('name')}` status=`{cp.get('status')}` summary=`{json.dumps(cp.get('summary', {}), ensure_ascii=False)}`")
    lines += ["", "## Reports"]
    for key, value in payload.get("reports", {}).items():
        lines.append(f"- `{key}`: `{value}`")
    write_markdown(out_dir / "cai-superior-summary.md", lines)


def _safe_stage(checkpoints: dict[str, dict[str, Any]], key: str, name: str, action, component: str) -> Any:
    try:
        return action()
    except Exception as exc:
        checkpoints[key] = {"checkpoint": key, "name": name, "status": "handled_error", "summary": handled_error(component="cai_implementation", action=component, error=exc)}
        return None


def run_cai_superior(target: str, *, include_subdomains: bool = False, criticality: str = "normal") -> dict[str, Any]:
    target = normalize_target(target)
    checkpoints: dict[str, dict[str, Any]] = {}
    print(BANNER, flush=True)
    print(f"[CAI] Target: {target}", flush=True)

    write_catalog()
    sensors = _safe_stage(checkpoints, "agentic-sensors", "Agentic Sensors", lambda: sensor_config(target), "agentic_sensors")
    if sensors is not None:
        checkpoints["agentic-sensors"] = write_sensor_config(target, sensors)
        record_sensor_event(target, "user_command", {"mode": "cai_superior_cli", "include_subdomains": include_subdomains, "criticality": criticality})
    plan = _safe_stage(checkpoints, "agentic-brain", "Agentic Brain Planner", lambda: build_plan(target, include_subdomains=include_subdomains, criticality=criticality, force=False), "agentic_brain")
    if plan is not None:
        checkpoints["agentic-brain"] = write_plan(target, plan)
        record_event(target, "brain_plan_created", {"decision": plan.get("decision", {})})

    profile = _safe_stage(checkpoints, "0", "System Initialization and Target Profiler", lambda: build_target_profile(target, include_subdomains=include_subdomains), "layer0")
    if profile is not None:
        checkpoints["0"] = write_profile_reports(profile)
    else:
        profile = {"target": target, "status": "missing_profile"}

    recon = _safe_stage(checkpoints, "1", "Reconnaissance and Asset Discovery Agent", lambda: run_recon(target, include_subdomains=include_subdomains), "layer1")
    if recon is not None:
        checkpoints["1"] = write_recon_reports(target, profile, recon)

    inventory = _safe_stage(checkpoints, "2", "Parameter and Endpoint Analysis Agent", lambda: build_inventory(target), "layer2")
    if inventory is not None:
        checkpoints["2"] = write_inventory_reports(target, inventory)

    matrix = _safe_stage(checkpoints, "3", "Review Matrix Agent", lambda: generate_hypotheses(target), "layer3")
    if matrix is not None:
        checkpoints["3"] = write_hypothesis_reports(target, matrix)

    evidence_review = _safe_stage(checkpoints, "4", "Non-Intrusive Evidence Review Agent", lambda: verify_from_existing_evidence(target), "layer4")
    if evidence_review is not None:
        checkpoints["4"] = write_verification_reports(target, evidence_review)

    scored = _safe_stage(checkpoints, "5", "Confidence Scoring and Evidence Engine", lambda: build_evidence_layer(target), "layer5")
    if scored is not None:
        checkpoints["5"] = write_evidence_reports(target, scored)

    prioritized = _safe_stage(checkpoints, "6", "Deduplication and Prioritization Agent", lambda: build_prioritization(target), "layer6")
    if prioritized is not None:
        checkpoints["6"] = write_prioritization_reports(target, prioritized)

    reports = _safe_stage(checkpoints, "7", "Report Generation Agent", lambda: build_reports(target), "layer7")
    if reports is not None:
        checkpoints["7"] = write_report_outputs(target, reports)

    learning = _safe_stage(checkpoints, "learning", "Autonomous Learning and Knowledge Graph", lambda: update_learning_db(target), "learning")
    if learning is not None:
        checkpoints["learning"] = write_learning_reports(target, learning)

    risk = _safe_stage(checkpoints, "adaptive-risk", "Predictive Modeling and Adaptive Risk Scoring", lambda: build_adaptive_risk(target, criticality=criticality), "adaptive_risk")
    if risk is not None:
        checkpoints["adaptive-risk"] = write_adaptive_risk_reports(target, risk)

    business = _safe_stage(checkpoints, "business-review", "Business Workflow Review", lambda: build_business_review(target), "business_review")
    if business is not None:
        checkpoints["business-review"] = write_business_review_reports(target, business)

    feedback = _safe_stage(checkpoints, "feedback", "Continuous Feedback Calibration", lambda: calibration_summary(target), "feedback")
    if feedback is not None:
        checkpoints["feedback"] = write_feedback_reports(target, feedback)

    memory_payload = _safe_stage(checkpoints, "agentic-memory", "Agentic Memory", lambda: ingest_scan_outputs(target), "agentic_memory")
    if memory_payload is not None:
        checkpoints["agentic-memory"] = write_memory_report(target, memory_payload)
        observe(target)

    payload = build_run_summary(target, checkpoints)
    write_run_summary(target, payload)
    write_log(f"CAI implementation completed for {target}")
    print("[CAI] Completed. Summary reports:", flush=True)
    print(json.dumps(payload.get("reports", {}), indent=2), flush=True)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI implementation zero-impact orchestrator")
    parser.add_argument("--target", required=True)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", default="normal", choices=["low", "normal", "high", "critical"])
    args = parser.parse_args()
    run_cai_superior(args.target, include_subdomains=args.include_subdomains, criticality=args.criticality)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
