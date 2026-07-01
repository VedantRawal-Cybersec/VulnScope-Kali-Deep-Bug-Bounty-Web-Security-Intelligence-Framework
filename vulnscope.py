#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

VERSION = "1.2.0-agentic-react"
OUT = Path("reports/output/vulnscope-main")
AUTH = Path("reports/output/authorization/vulnscope-session-confirmation.json")

BANNER = """
╔════════════════════════════════════════════════════════════════════╗
║                         VulnScope                                ║
║           Single safe launcher for authorized review              ║
╚════════════════════════════════════════════════════════════════════╝
"""


def normalize_target(raw: str) -> str:
    raw = str(raw or "").strip()
    if not raw:
        raise ValueError("target is required")
    return raw if "://" in raw else "https://" + raw


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = (parsed.hostname or parsed.netloc or "").split(":")[0].lower().strip()
    if not host:
        raise ValueError("invalid target")
    return host


def run(label: str, command: list[str], timeout: int = 3600) -> dict:
    print(f"\n[{label}]")
    print("$ " + " ".join(command))
    started = datetime.now(timezone.utc)
    try:
        proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        print(proc.stdout[-4000:])
        return {"label": label, "ok": proc.returncode == 0, "exit_code": proc.returncode, "command": command, "output_tail": proc.stdout[-4000:]}
    except Exception as exc:
        print(f"error: {exc}")
        return {"label": label, "ok": False, "error": str(exc), "command": command, "started_at": started.isoformat()}


def confirm(target: str, yes: bool) -> None:
    print(BANNER)
    print("Authorized use only. Scope is locked to the target you provide.")
    print(f"Target: {target}")
    if not yes and os.getenv("VULNSCOPE_AUTHORIZED", "0") != "1":
        answer = input("Type YES to confirm authorization: ").strip()
        if answer != "YES":
            raise SystemExit("Authorization not confirmed.")
    AUTH.parent.mkdir(parents=True, exist_ok=True)
    AUTH.write_text(json.dumps({"target": target, "host": host_from_target(target), "confirmed_authorization": True, "confirmed_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")


def final_summary(target: str, history: list[dict]) -> None:
    host = host_from_target(target)
    reports = {
        "react_loop": f"reports/output/cai-superior/{host}/react-run.md",
        "react_state": f"reports/output/cai-superior/{host}/react-state.md",
        "cai_summary": f"reports/output/cai-superior/{host}/cai-superior-summary.md",
        "final_dashboard": f"reports/output/final-dashboard/{host}-dashboard.html",
        "authorization": str(AUTH),
    }
    payload = {"target": target, "history": history, "reports": reports, "generated_at": datetime.now(timezone.utc).isoformat()}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "final-summary.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# VulnScope Summary", "", f"Target: `{target}`", "", "## Steps"]
    for item in history:
        lines.append(f"- `{item.get('label')}` ok=`{item.get('ok')}` exit=`{item.get('exit_code', 'n/a')}`")
    lines += ["", "## Reports"]
    for name, path in reports.items():
        lines.append(f"- `{name}`: `{path}`")
    (OUT / "final-summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\nOpen reports:")
    for path in reports.values():
        print("- " + path)


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope single safe launcher")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", "--url", dest="target", default="")
    parser.add_argument("--mode", choices=["deps", "cai", "agentic"], default="agentic")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--criticality", choices=["low", "normal", "high", "critical"], default="normal")
    parser.add_argument("--max-turns", type=int, default=15)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--install-python", action="store_true")
    parser.add_argument("--clone-cai-reference", action="store_true")
    args = parser.parse_args()
    if args.version:
        print(VERSION)
        return 0
    target = normalize_target(args.target or input("Target URL/domain: ").strip())
    confirm(target, args.yes)
    history: list[dict] = []
    if args.mode == "deps":
        cmd = [sys.executable, "cai_dependency_manager_cli.py"]
        if args.install_python:
            cmd.append("--install-python")
        if args.clone_cai_reference:
            cmd.append("--clone-cai-reference")
        history.append(run("Dependency readiness", cmd, timeout=900))
    elif args.mode == "cai":
        cmd = [sys.executable, "cai_superior_cli.py", "--target", target, "--criticality", args.criticality]
        if args.include_subdomains:
            cmd.append("--include-subdomains")
        history.append(run("CAI checkpoint pipeline", cmd, timeout=3600))
    else:
        cmd = [sys.executable, "-m", "core.react_loop", "--target", target, "--max-turns", str(args.max_turns), "--criticality", args.criticality]
        if args.include_subdomains:
            cmd.append("--include-subdomains")
        if args.force:
            cmd.append("--force")
        history.append(run("Safe ReAct loop", cmd, timeout=3600))
    final_summary(target, history)
    return 0 if all(x.get("ok") for x in history) else 1


if __name__ == "__main__":
    raise SystemExit(main())
