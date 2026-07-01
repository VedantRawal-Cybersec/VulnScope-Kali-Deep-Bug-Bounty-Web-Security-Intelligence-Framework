#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from typing import Any

from cai_error_handler import handled_error, write_json, write_log, write_markdown
from cai_hypothesis_agent_cli import generate_hypotheses, write_hypothesis_reports
from cai_parameter_analysis_cli import build_inventory, write_inventory_reports
from cai_recon_agent_cli import run_recon, write_recon_reports
from cai_scope_guard import cai_output_dir, normalize_target
from cai_target_profiler_cli import build_target_profile, write_profile_reports
from cai_verification_agent_cli import verify_from_existing_evidence, write_verification_reports

BANNER = r"""
╔════════════════════════════════════════════════════════════════════╗
║                  CAI SUPERIOR — ZERO IMPACT MODE                  ║
║       Profile → Passive Recon → Input Inventory → Review Matrix   ║
╚════════════════════════════════════════════════════════════════════╝
"""


def build_run_summary(target: str, checkpoints: dict[str, dict[str, Any]]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    return {
        "target": normalize_target(target),
        "generated_at": time.time(),
        "status": "completed",
        "layers_completed": [int(x) for x in sorted(checkpoints.keys(), key=int)],
        "checkpoints": checkpoints,
        "reports": {
            "run_summary_json": str(out_dir / "cai-superior-summary.json"),
            "run_summary_md": str(out_dir / "cai-superior-summary.md"),
            "target_profile_json": str(out_dir / "target-profile.json"),
            "target_profile_md": str(out_dir / "target-profile.md"),
            "recon_json": str(out_dir / "recon-agent.json"),
            "recon_md": str(out_dir / "recon-agent.md"),
            "asset_graph_json": str(out_dir / "asset-graph.json"),
            "asset_graph_md": str(out_dir / "asset-graph.md"),
            "input_inventory_json": str(out_dir / "input-inventory.json"),
            "input_inventory_md": str(out_dir / "input-inventory.md"),
            "review_matrix_json": str(out_dir / "hypothesis-matrix.json"),
            "review_matrix_md": str(out_dir / "hypothesis-matrix.md"),
            "evidence_review_json": str(out_dir / "verification-results.json"),
            "evidence_review_md": str(out_dir / "verification-results.md"),
        },
    }


def write_run_summary(target: str, payload: dict[str, Any]) -> None:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "cai-superior-summary.json", payload)
    lines = ["# CAI Superior Summary", "", f"Target: `{payload.get('target')}`", f"Status: `{payload.get('status')}`", f"Layers completed: `{', '.join(str(x) for x in payload.get('layers_completed', []))}`", "", "## Checkpoints"]
    for key in sorted(payload.get("checkpoints", {}), key=int):
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
        checkpoints[key] = {"checkpoint": int(key), "name": name, "status": "handled_error", "summary": handled_error(component="cai_superior", action=component, error=exc)}
        return None


def run_cai_superior(target: str, *, include_subdomains: bool = False) -> dict[str, Any]:
    target = normalize_target(target)
    checkpoints: dict[str, dict[str, Any]] = {}
    print(BANNER, flush=True)
    print(f"[CAI] Target: {target}", flush=True)

    print("[CAI] Layer 0", flush=True)
    profile = _safe_stage(checkpoints, "0", "System Initialization & Target Profiler", lambda: build_target_profile(target, include_subdomains=include_subdomains), "layer0")
    if profile is not None:
        checkpoints["0"] = write_profile_reports(profile)
    else:
        profile = {"target": target, "status": "missing_profile"}

    print("[CAI] Layer 1", flush=True)
    recon = _safe_stage(checkpoints, "1", "Reconnaissance & Asset Discovery Agent", lambda: run_recon(target, include_subdomains=include_subdomains), "layer1")
    if recon is not None:
        checkpoints["1"] = write_recon_reports(target, profile, recon)

    print("[CAI] Layer 2", flush=True)
    inventory = _safe_stage(checkpoints, "2", "Parameter & Endpoint Analysis Agent", lambda: build_inventory(target), "layer2")
    if inventory is not None:
        checkpoints["2"] = write_inventory_reports(target, inventory)

    print("[CAI] Layer 3", flush=True)
    matrix = _safe_stage(checkpoints, "3", "Review Matrix Agent", lambda: generate_hypotheses(target), "layer3")
    if matrix is not None:
        checkpoints["3"] = write_hypothesis_reports(target, matrix)

    print("[CAI] Layer 4", flush=True)
    evidence = _safe_stage(checkpoints, "4", "Evidence Review Agent", lambda: verify_from_existing_evidence(target), "layer4")
    if evidence is not None:
        checkpoints["4"] = write_verification_reports(target, evidence)

    payload = build_run_summary(target, checkpoints)
    write_run_summary(target, payload)
    write_log(f"CAI Superior completed layers {payload.get('layers_completed')} for {target}")
    print("[CAI] Completed. Summary reports:", flush=True)
    print(json.dumps(payload.get("reports", {}), indent=2), flush=True)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI Superior zero-impact orchestrator")
    parser.add_argument("--target", required=True)
    parser.add_argument("--include-subdomains", action="store_true")
    args = parser.parse_args()
    run_cai_superior(args.target, include_subdomains=args.include_subdomains)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
