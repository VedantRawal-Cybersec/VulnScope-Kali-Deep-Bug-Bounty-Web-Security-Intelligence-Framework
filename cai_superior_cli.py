#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from typing import Any

from cai_error_handler import handled_error, write_json, write_log, write_markdown
from cai_recon_agent_cli import run_recon, write_recon_reports
from cai_scope_guard import cai_output_dir, normalize_target
from cai_target_profiler_cli import build_target_profile, write_profile_reports

BANNER = r"""
╔════════════════════════════════════════════════════════════════════╗
║                  CAI SUPERIOR — ZERO IMPACT MODE                  ║
║        Layer 0 Target Profile → Layer 1 Passive Asset Graph        ║
╚════════════════════════════════════════════════════════════════════╝
"""


def build_run_summary(target: str, profile_checkpoint: dict[str, Any], recon_checkpoint: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(target)
    return {
        "target": normalize_target(target),
        "generated_at": time.time(),
        "status": "completed",
        "layers_completed": [0, 1],
        "checkpoints": {
            "0": profile_checkpoint,
            "1": recon_checkpoint,
        },
        "reports": {
            "run_summary_json": str(out_dir / "cai-superior-summary.json"),
            "run_summary_md": str(out_dir / "cai-superior-summary.md"),
            "target_profile_json": str(out_dir / "target-profile.json"),
            "target_profile_md": str(out_dir / "target-profile.md"),
            "recon_json": str(out_dir / "recon-agent.json"),
            "recon_md": str(out_dir / "recon-agent.md"),
            "asset_graph_json": str(out_dir / "asset-graph.json"),
            "asset_graph_md": str(out_dir / "asset-graph.md"),
        },
    }


def write_run_summary(target: str, payload: dict[str, Any]) -> None:
    out_dir = cai_output_dir(target)
    write_json(out_dir / "cai-superior-summary.json", payload)
    c0 = payload.get("checkpoints", {}).get("0", {}).get("summary", {})
    c1 = payload.get("checkpoints", {}).get("1", {}).get("summary", {})
    lines = [
        "# CAI Superior Layer 0–1 Summary",
        "",
        f"Target: `{payload.get('target')}`",
        f"Status: `{payload.get('status')}`",
        f"Layers completed: `{', '.join(str(x) for x in payload.get('layers_completed', []))}`",
        "",
        "## Checkpoint 0 — Target Profile",
        f"- IP count: `{c0.get('ip_count', 0)}`",
        f"- WAF/CDN detected: `{c0.get('cdn_waf_detected', False)}`",
        f"- Production classification: `{c0.get('production_classification')}`",
        f"- TLS status: `{c0.get('tls_status')}`",
        "",
        "## Checkpoint 1 — Passive Recon",
        f"- Subdomains: `{c1.get('subdomains', 0)}`",
        f"- Historical URLs: `{c1.get('historical_urls', 0)}`",
        f"- Asset graph nodes: `{c1.get('asset_graph_nodes', 0)}`",
        f"- Asset graph edges: `{c1.get('asset_graph_edges', 0)}`",
        "",
        "## Reports",
    ]
    for key, value in payload.get("reports", {}).items():
        lines.append(f"- `{key}`: `{value}`")
    write_markdown(out_dir / "cai-superior-summary.md", lines)


def run_cai_superior(target: str, *, include_subdomains: bool = False) -> dict[str, Any]:
    target = normalize_target(target)
    print(BANNER, flush=True)
    print(f"[CAI] Target: {target}", flush=True)
    print("[CAI] Running Layer 0 target profiler...", flush=True)
    try:
        profile = build_target_profile(target, include_subdomains=include_subdomains)
        c0 = write_profile_reports(profile)
    except Exception as exc:
        profile = {"target": target, "status": "profile_failed", "error": handled_error(component="cai_superior", action="layer0", error=exc)}
        c0 = {"checkpoint": 0, "status": "handled_error", "summary": profile.get("error", {})}
    print("[CAI] Running Layer 1 passive reconnaissance...", flush=True)
    try:
        recon = run_recon(target, include_subdomains=include_subdomains)
        c1 = write_recon_reports(target, profile, recon)
    except Exception as exc:
        c1 = {"checkpoint": 1, "status": "handled_error", "summary": handled_error(component="cai_superior", action="layer1", error=exc)}
    payload = build_run_summary(target, c0, c1)
    write_run_summary(target, payload)
    write_log(f"CAI Superior Layer 0-1 completed for {target}")
    print("[CAI] Layer 0–1 completed. Summary:", flush=True)
    print(json.dumps(payload.get("reports", {}), indent=2), flush=True)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI Superior zero-impact Layer 0-1 orchestrator")
    parser.add_argument("--target", required=True)
    parser.add_argument("--include-subdomains", action="store_true")
    args = parser.parse_args()
    run_cai_superior(args.target, include_subdomains=args.include_subdomains)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
