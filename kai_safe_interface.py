#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

from dependency_manager import run_preflight_repair
from target_scope_guard import reset_target_report_state

OUT = Path("reports/output/kai-interface")

BANNER = r"""
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║        VULNSCOPE — DIRECT AUTONOMOUS SCAN INTERFACE                ║
║        Target → Consent → Crazy Live Autonomous Engine              ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
"""


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("Target cannot be empty")
    return raw if "://" in raw else "https://" + raw


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = parsed.hostname or parsed.netloc or target.replace("https://", "").replace("http://", "").split("/")[0]
    if not host:
        raise ValueError("Invalid target")
    return host.lower()


def domain_slug(target: str) -> str:
    host = host_from_target(target)
    return re.sub(r"[^a-z0-9.-]+", "-", host.lower()).strip("-.") or "target"


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    raw = input(f"{prompt} {suffix}: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}


def ask_target_and_consent() -> dict:
    print(BANNER)
    print("This mode does not ask for any config YAML file.")
    print("It asks for the target URL, asks for your authorization confirmation, then starts the crazy live autonomous scan.\n")

    target = normalize_target(input("Enter target URL/domain: ").strip())
    host = host_from_target(target)

    print("\nAUTHORIZATION CONFIRMATION")
    print(f"Target: {target}")
    print("Confirm the following before continuing:")
    print("- You own this target OR you have explicit written permission to security-test it.")
    print("- You accept responsibility for running the scan on this target.")
    print("- VulnScope will scope-lock the run to this host and safe review modules.")
    print("- Unauthorized testing is not allowed.")
    confirm = input("Type YES if you own/have full authorization to test this target: ").strip()
    if confirm != "YES":
        raise SystemExit("Consent not confirmed. Exiting.")

    include_subdomains = ask_yes_no("Include subdomains in scope?", False)
    two_accounts = ask_yes_no("Use saved two-account comparison if available?", False)

    session = {
        "target": target,
        "host": host,
        "include_subdomains": include_subdomains,
        "two_accounts": two_accounts,
        "confirmed_authorization": True,
        "confirmed_at": time.time(),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "direct-session.json").write_text(json.dumps(session, indent=2), encoding="utf-8")
    return session


def build_command(session: dict) -> list[str]:
    cmd = [
        "python3",
        "autonomous_live_cli.py",
        "--target",
        session["target"],
        "--max-cycles",
        "8",
        "--max-workers",
        "8",
    ]
    if session.get("include_subdomains"):
        cmd.append("--include-subdomains")
    if session.get("two_accounts"):
        cmd.append("--include-google-pair")
    return cmd


def build_scan_env(session: dict) -> dict[str, str]:
    env = dict(os.environ)
    env["VULNSCOPE_TARGET"] = str(session["target"])
    env["VULNSCOPE_TARGET_HOST"] = str(session["host"])
    env["VULNSCOPE_INCLUDE_SUBDOMAINS"] = "1" if session.get("include_subdomains") else "0"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def run_domain_finding_brief(session: dict) -> None:
    print("\n[+] Generating short per-domain finding brief")
    brief_cmd = ["python3", "domain_finding_brief_cli.py", "--target", session["target"]]
    print("$ " + " ".join(brief_cmd))
    brief_code = subprocess.call(brief_cmd, env=build_scan_env(session))
    slug = domain_slug(session["target"])
    print(f"[+] Finding brief exit code: {brief_code}")
    print(f"[+] Markdown: reports/output/domain-reports/{slug}-finding-brief.md")
    print(f"[+] JSON: reports/output/domain-reports/{slug}-finding-brief.json")


def main() -> int:
    session = ask_target_and_consent()

    print("\n[+] Enforcing target isolation for this run")
    isolation = reset_target_report_state(session)
    session["target_isolation"] = isolation
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "direct-session.json").write_text(json.dumps(session, indent=2), encoding="utf-8")
    print(f"[+] Scope locked to: {session['target']} ({session['host']})")
    print(f"[+] Removed stale previous outputs: {len(isolation.get('removed_previous_outputs', []))}")

    print("\n[+] Running visible preflight helper-tool check")
    doctor_code = run_preflight_repair(repair=True)
    if doctor_code != 0:
        print("[!] Preflight returned a non-zero exit code. Continuing because helper tools are optional.")

    cmd = build_command(session)
    print("\n[+] Starting crazy live autonomous scan now")
    print("$ " + " ".join(cmd))
    code = subprocess.call(cmd, env=build_scan_env(session))

    run_domain_finding_brief(session)

    if code == 0:
        print("\n[+] Scan finished successfully. Open these reports:")
    else:
        print(f"\n[!] Scan exited with code {code}. Open the reports/logs below to see the exact failing module:")
    print("- reports/output/autonomous-live/live-run.md")
    print("- reports/output/autonomous-live/live-run.json")
    print("- reports/output/vulnscope-main/final-summary.md")
    print("- reports/output/mission-verdicts/mission-verdicts.md")
    print("- reports/output/report-v2/executive-report-v2.md")
    print(f"- reports/output/domain-reports/{domain_slug(session['target'])}-finding-brief.md")
    print("- reports/output/kai-interface/direct-session.json")
    print("- reports/output/current-target-session.json")
    print("- reports/output/tool-doctor/tool-doctor.md")
    print("- reports/output/tool-doctor/tool-doctor-install.log")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
