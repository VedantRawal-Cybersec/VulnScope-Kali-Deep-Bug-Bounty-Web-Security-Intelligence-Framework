#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

from scope.policy import load_scope_policy

OUT = Path("reports/output/control-center")
STATE = OUT / "state.json"
EVENTS = OUT / "events.jsonl"
CONFIG_DEFAULT = Path("autonomous_control_config.yaml")


@dataclass
class ControlConfig:
    targets: list[str]
    scope_policy: str = "scope_policy.yaml"
    interval_minutes: int = 360
    max_cycles: int = 8
    enable_tool_mind: bool = True
    enable_artemis: bool = True
    enable_aegis_safe: bool = True
    enable_proxy_passive_bridge: bool = True
    enable_google_pair: bool = False
    enable_final_report: bool = True
    notes: str = "Safe authorized-only autonomy."


def write_default_config(path: str | Path = CONFIG_DEFAULT) -> Path:
    data = ControlConfig(targets=["https://example.com"])
    p = Path(path)
    if yaml:
        p.write_text(yaml.safe_dump(asdict(data), sort_keys=False), encoding="utf-8")
    else:
        p.write_text(json.dumps(asdict(data), indent=2), encoding="utf-8")
    return p


def load_config(path: str | Path = CONFIG_DEFAULT) -> ControlConfig:
    p = Path(path)
    if not p.exists():
        write_default_config(p)
    text = p.read_text(encoding="utf-8", errors="ignore")
    if p.suffix.lower() in {".yaml", ".yml"} and yaml:
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text) if text.strip() else {}
    return ControlConfig(
        targets=list(data.get("targets") or []),
        scope_policy=str(data.get("scope_policy", "scope_policy.yaml")),
        interval_minutes=int(data.get("interval_minutes", 360)),
        max_cycles=int(data.get("max_cycles", 8)),
        enable_tool_mind=bool(data.get("enable_tool_mind", True)),
        enable_artemis=bool(data.get("enable_artemis", True)),
        enable_aegis_safe=bool(data.get("enable_aegis_safe", True)),
        enable_proxy_passive_bridge=bool(data.get("enable_proxy_passive_bridge", True)),
        enable_google_pair=bool(data.get("enable_google_pair", False)),
        enable_final_report=bool(data.get("enable_final_report", True)),
        notes=str(data.get("notes", "Safe authorized-only autonomy.")),
    )


def event(event_type: str, payload: dict[str, Any] | None = None, level: str = "info") -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    row = {"ts": time.time(), "type": event_type, "level": level, "payload": payload or {}}
    with EVENTS.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_state() -> dict[str, Any]:
    if not STATE.exists():
        return {"running": False, "last_run": None, "targets": []}
    try:
        return json.loads(STATE.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {"running": False, "last_run": None, "targets": []}


def save_state(data: dict[str, Any]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def run_command(label: str, command: str, timeout: int = 3600) -> dict[str, Any]:
    event("phase_started", {"label": label, "command": command})
    started = time.time()
    proc = subprocess.run(["bash", "-lc", command], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    result = {
        "label": label,
        "command": command,
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "seconds": round(time.time() - started, 2),
        "output_tail": proc.stdout[-4000:],
    }
    event("phase_finished", {"label": label, "ok": result["ok"], "seconds": result["seconds"]}, "info" if result["ok"] else "warning")
    return result


def build_phases(target: str, cfg: ControlConfig) -> list[tuple[str, str, int]]:
    phases: list[tuple[str, str, int]] = []
    if cfg.enable_tool_mind:
        phases += [
            ("Tool Mind", f"python3 tool_mind_cli.py --target {target} --mode crazy --install-needed --yes", 3600),
            ("Tool PATH Repair", "python3 tool_path_repair_cli.py", 600),
        ]
    if cfg.enable_artemis:
        phases.append(("ARTEMIS Passive Intelligence", f"python3 artemis_autonomous_cli.py --config artemis_config.yaml --scope-policy {cfg.scope_policy} --once", 1800))
    phases += [
        ("AEGIS Public Search", f"python3 aegis_public_search_cli.py --target {target}", 600),
        ("AEGIS Feedback Planner", f"python3 aegis_feedback_cli.py --target {target}", 600),
    ]
    if cfg.enable_aegis_safe:
        phases.append(("AEGIS-SAFE", f"python3 safe_aegis_cli.py --target {target} --scope-policy {cfg.scope_policy} --cycles {cfg.max_cycles} --yes", 3600))
    if cfg.enable_proxy_passive_bridge:
        phases.append(("Proxy Passive Bridge", f"python3 artemis_proxy_passive_cli.py --target {target} --limit 80", 600))
    if cfg.enable_google_pair:
        phases.append(("Google A/B Precision", f"python3 google_pair_cli.py --target {target} --profile default --max-pages 25 --skip-login --yes", 3600))
    phases += [
        ("Advanced Correlation", f"python3 vulnscope_modes_cli.py --target {target} --scope-policy {cfg.scope_policy}", 1800),
        ("Evidence Cards", f"python3 evidence_cards_cli.py --target {target}", 600),
        ("Reportability", f"python3 reportability_cli.py --target {target}", 600),
    ]
    if cfg.enable_final_report:
        phases += [
            ("Final Report", f"python3 report_v2_cli.py --target {target}", 600),
            ("JARVIS Summary", f"python3 jarvis_summary_cli.py --target {target}", 600),
        ]
    return phases


def run_once(cfg: ControlConfig) -> dict[str, Any]:
    policy = load_scope_policy(cfg.scope_policy)
    started = time.time()
    state = {"running": True, "started_at": started, "config": asdict(cfg), "targets": [], "current_phase": None}
    save_state(state)
    event("control_run_started", {"targets": cfg.targets, "scope_policy": cfg.scope_policy})
    target_rows = []
    for target in cfg.targets:
        decision = policy.check(target)
        row: dict[str, Any] = {"target": target, "allowed": decision.allowed, "reason": decision.reason, "phases": []}
        if not decision.allowed:
            event("target_blocked", {"target": target, "reason": decision.reason}, "warning")
            target_rows.append(row)
            continue
        for label, command, timeout in build_phases(target, cfg):
            state["current_phase"] = {"target": target, "label": label, "command": command, "started_at": time.time()}
            save_state(state)
            result = run_command(label, command, timeout=timeout)
            row["phases"].append(result)
            if not result["ok"] and label in {"Tool Mind", "AEGIS-SAFE"}:
                break
        target_rows.append(row)
    finished = time.time()
    final_state = {
        "running": False,
        "started_at": started,
        "ended_at": finished,
        "seconds": round(finished - started, 2),
        "last_run": {"targets": target_rows, "seconds": round(finished - started, 2)},
        "targets": target_rows,
        "current_phase": None,
        "outputs": {
            "jarvis": "inline terminal output",
            "control_state": str(STATE),
            "events": str(EVENTS),
            "final_report": "reports/output/report-v2/executive-report-v2.md",
            "evidence_cards": "reports/output/evidence-cards/evidence-cards.md",
            "artemis": "reports/output/artemis/run/artemis-run.md",
        },
    }
    save_state(final_state)
    event("control_run_finished", {"seconds": final_state["seconds"], "targets": len(target_rows)})
    return final_state


def run_forever(cfg: ControlConfig) -> None:
    while True:
        run_once(cfg)
        time.sleep(max(60, cfg.interval_minutes * 60))


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope safe autonomous control daemon")
    parser.add_argument("--config", default=str(CONFIG_DEFAULT))
    parser.add_argument("--init-config", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--forever", action="store_true")
    args = parser.parse_args()
    if args.init_config:
        print(json.dumps({"created": str(write_default_config(args.config))}, indent=2))
        return 0
    cfg = load_config(args.config)
    result = run_once(cfg) if not args.forever else None
    if args.forever:
        run_forever(cfg)
    else:
        print(json.dumps({"state": str(STATE), "seconds": result.get("seconds") if result else None}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
