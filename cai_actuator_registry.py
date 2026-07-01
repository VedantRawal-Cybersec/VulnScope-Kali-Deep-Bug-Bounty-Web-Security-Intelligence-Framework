#!/usr/bin/env python3
from __future__ import annotations

import inspect
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable

from cai_error_handler import handled_error, write_json, write_markdown
from cai_scope_guard import normalize_target


@dataclass(frozen=True)
class Actuator:
    name: str
    description: str
    parameters: dict[str, str]
    safe: bool = True
    writes_target_data: bool = False
    requires_human_approval: bool = False


def _target_param() -> dict[str, str]:
    return {"target": "Authorized root URL or domain locked by the scope guard."}


ACTUATORS: dict[str, Actuator] = {
    "dependency_status": Actuator("dependency_status", "Check CAI framework package and tool readiness without touching the target.", {}),
    "target_profile": Actuator("target_profile", "Build passive target profile: DNS, WHOIS/ASN where available, CDN/WAF hints, TLS fingerprint.", _target_param()),
    "passive_recon": Actuator("passive_recon", "Collect passive asset signals from CT logs, archives, and installed passive recon tools.", {**_target_param(), "include_subdomains": "Whether explicit scope includes subdomains."}),
    "input_inventory": Actuator("input_inventory", "Extract endpoint inputs from already discovered URLs without sending new requests.", _target_param()),
    "hypothesis_matrix": Actuator("hypothesis_matrix", "Rank review hypotheses from endpoint/input context and cost-benefit scoring.", _target_param()),
    "evidence_review": Actuator("evidence_review", "Match hypotheses against already collected safe evidence artifacts.", _target_param()),
    "evidence_scoring": Actuator("evidence_scoring", "Apply evidence-based confidence scoring to existing review artifacts.", _target_param()),
    "prioritize": Actuator("prioritize", "Deduplicate and prioritize scored findings by endpoint, input, type, and impact.", _target_param()),
    "report": Actuator("report", "Generate platform-ready reports for confirmed findings and review leads.", _target_param()),
    "learning": Actuator("learning", "Update local knowledge graph and memory store from scan outputs.", _target_param()),
    "adaptive_risk": Actuator("adaptive_risk", "Adjust risk using business context and user criticality settings.", {**_target_param(), "criticality": "low, normal, high, or critical."}),
    "business_review": Actuator("business_review", "Plan safe manual workflow review candidates; never executes state-changing actions.", _target_param()),
    "feedback": Actuator("feedback", "Summarize local report feedback calibration state.", _target_param()),
}


def actuator_catalog() -> dict[str, Any]:
    return {
        "generated_at": time.time(),
        "actuators": [asdict(x) for x in ACTUATORS.values()],
        "safety_contract": {
            "target_data_modification": False,
            "unsafe_methods": False,
            "bruteforce": False,
            "exploit_execution": False,
            "all_functions_have_descriptions": True,
        },
    }


def call_actuator(name: str, *, target: str = "", include_subdomains: bool = False, criticality: str = "normal") -> dict[str, Any]:
    target = normalize_target(target) if target else target
    try:
        if name == "dependency_status":
            from cai_dependency_manager_cli import build_dependency_report
            return build_dependency_report()
        if name == "target_profile":
            from cai_target_profiler_cli import build_target_profile, write_profile_reports
            payload = build_target_profile(target, include_subdomains=include_subdomains)
            return {"payload": payload, "checkpoint": write_profile_reports(payload)}
        if name == "passive_recon":
            from cai_target_profiler_cli import build_target_profile
            from cai_recon_agent_cli import run_recon, write_recon_reports
            profile = build_target_profile(target, include_subdomains=include_subdomains)
            payload = run_recon(target, include_subdomains=include_subdomains)
            return {"payload": payload, "checkpoint": write_recon_reports(target, profile, payload)}
        if name == "input_inventory":
            from cai_parameter_analysis_cli import build_inventory, write_inventory_reports
            payload = build_inventory(target)
            return {"payload": payload, "checkpoint": write_inventory_reports(target, payload)}
        if name == "hypothesis_matrix":
            from cai_hypothesis_agent_cli import generate_hypotheses, write_hypothesis_reports
            payload = generate_hypotheses(target)
            return {"payload": payload, "checkpoint": write_hypothesis_reports(target, payload)}
        if name == "evidence_review":
            from cai_verification_agent_cli import verify_from_existing_evidence, write_verification_reports
            payload = verify_from_existing_evidence(target)
            return {"payload": payload, "checkpoint": write_verification_reports(target, payload)}
        if name == "evidence_scoring":
            from cai_evidence_engine_cli import build_evidence_layer, write_evidence_reports
            payload = build_evidence_layer(target)
            return {"payload": payload, "checkpoint": write_evidence_reports(target, payload)}
        if name == "prioritize":
            from cai_prioritization_cli import build_prioritization, write_prioritization_reports
            payload = build_prioritization(target)
            return {"payload": payload, "checkpoint": write_prioritization_reports(target, payload)}
        if name == "report":
            from cai_report_agent_cli import build_reports, write_report_outputs
            payload = build_reports(target)
            return {"payload": payload, "checkpoint": write_report_outputs(target, payload)}
        if name == "learning":
            from cai_learning_cli import update_learning_db, write_learning_reports
            payload = update_learning_db(target)
            return {"payload": payload, "checkpoint": write_learning_reports(target, payload)}
        if name == "adaptive_risk":
            from cai_adaptive_risk_cli import build_adaptive_risk, write_adaptive_risk_reports
            payload = build_adaptive_risk(target, criticality=criticality)
            return {"payload": payload, "checkpoint": write_adaptive_risk_reports(target, payload)}
        if name == "business_review":
            from cai_business_logic_cli import build_business_review, write_business_review_reports
            payload = build_business_review(target)
            return {"payload": payload, "checkpoint": write_business_review_reports(target, payload)}
        if name == "feedback":
            from cai_feedback_cli import calibration_summary, write_feedback_reports
            payload = calibration_summary(target)
            return {"payload": payload, "checkpoint": write_feedback_reports(target, payload)}
        return {"status": "unknown_actuator", "name": name}
    except Exception as exc:
        return handled_error(component="actuator_registry", action=name, error=exc)


def write_catalog() -> dict[str, Any]:
    out = Path("reports/output/cai-superior/agentic")
    out.mkdir(parents=True, exist_ok=True)
    payload = actuator_catalog()
    write_json(out / "actuator-catalog.json", payload)
    lines = ["# CAI Actuator Catalog", "", "Every actuator is declared with typed parameters and a short description.", ""]
    for item in payload["actuators"]:
        lines.append(f"- `{item['name']}` — {item['description']} params=`{json.dumps(item['parameters'], ensure_ascii=False)}`")
    write_markdown(out / "actuator-catalog.md", lines)
    return payload


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="CAI typed actuator registry")
    parser.add_argument("--catalog", action="store_true")
    parser.add_argument("--call", default="")
    parser.add_argument("--target", default="")
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", default="normal")
    args = parser.parse_args()
    result = call_actuator(args.call, target=args.target, include_subdomains=args.include_subdomains, criticality=args.criticality) if args.call else write_catalog()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
