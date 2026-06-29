#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
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
    max_workers: int = 6
    enable_google_pair: bool = False
    notes: str = "Safe authorized-only autonomy. Unified parallel mission mode."


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
        max_workers=int(data.get("max_workers", 6)),
        enable_google_pair=bool(data.get("enable_google_pair", False)),
        notes=str(data.get("notes", "Safe authorized-only autonomy. Unified parallel mission mode.")),
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


def run_command(label: str, command: str, timeout: int = 7200) -> dict[str, Any]:
    event("phase_started", {"label": label, "command": command})
    started = time.time()
    proc = subprocess.run(["bash", "-lc", command], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    result = {
        "label": label,
        "command": command,
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "seconds": round(time.time() - started, 2),
        "output_tail": proc.stdout[-5000:],
    }
    event("phase_finished", {"label": label, "ok": result["ok"], "seconds": result["seconds"]}, "info" if result["ok"] else "warning")
    return result


def unified_command(target: str, cfg: ControlConfig) -> str:
    cmd = (
        "python3 unified_mission_cli.py "
        f"--target {shlex.quote(target)} "
        f"--scope-policy {shlex.quote(cfg.scope_policy)} "
        f"--max-cycles {cfg.max_cycles} "
        f"--max-workers {cfg.max_workers} "
        "--yes"
    )
    if cfg.enable_google_pair:
        cmd += " --include-google-pair"
    return cmd


def run_once(cfg: ControlConfig) -> dict[str, Any]:
    policy = load_scope_policy(cfg.scope_policy)
    started = time.time()
    state = {"running": True, "started_at": started, "config": asdict(cfg), "targets": [], "current_phase": None}
    save_state(state)
    event("control_run_started", {"targets": cfg.targets, "scope_policy": cfg.scope_policy, "mode": "unified_parallel"})
    target_rows = []
    for target in cfg.targets:
        decision = policy.check(target)
        row: dict[str, Any] = {"target": target, "allowed": decision.allowed, "reason": decision.reason, "phases": []}
        if not decision.allowed:
            event("target_blocked", {"target": target, "reason": decision.reason}, "warning")
            target_rows.append(row)
            continue
        cmd = unified_command(target, cfg)
        state["current_phase"] = {"target": target, "label": "Unified Parallel Mission", "command": cmd, "started_at": time.time()}
        save_state(state)
        result = run_command("Unified Parallel Mission", cmd, timeout=7200)
        row["phases"].append(result)
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
            "unified_mission": "reports/output/unified-mission/unified-mission.md",
            "jarvis": "inline terminal output",
            "control_state": str(STATE),
            "events": str(EVENTS),
            "final_report": "reports/output/report-v2/executive-report-v2.md",
            "evidence_cards": "reports/output/evidence-cards/evidence-cards.md",
            "artemis": "reports/output/artemis/run/artemis-run.md",
        },
    }
    save_state(final_state)
    event("control_run_finished", {"seconds": final_state["seconds"], "targets": len(target_rows), "mode": "unified_parallel"})
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
    if args.forever:
        run_forever(cfg)
        return 0
    result = run_once(cfg)
    print(json.dumps({"state": str(STATE), "seconds": result.get("seconds"), "mode": "unified_parallel"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
