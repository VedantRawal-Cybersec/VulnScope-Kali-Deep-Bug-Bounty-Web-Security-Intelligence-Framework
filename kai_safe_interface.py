#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

OUT = Path("reports/output/kai-interface")

BANNER = r'''
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║        VULNSCOPE — DIRECT AUTONOMOUS SCAN INTERFACE                ║
║        Target → Consent → Crazy Live Autonomous Engine              ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
'''


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


def main() -> int:
    session = ask_target_and_consent()
    print("\n[+] Repairing optional helper tools before autonomous scan")
    subprocess.call(["python3", "tool_doctor_cli.py", "--install", "--yes"])
    cmd = build_command(session)
    print("\n[+] Starting crazy live autonomous scan now")
    print("$ " + " ".join(cmd))
    code = subprocess.call(cmd)
    print("\n[+] Scan finished. Open these reports:")
    print("- reports/output/autonomous-live/live-run.md")
    print("- reports/output/vulnscope-main/final-summary.md")
    print("- reports/output/mission-verdicts/mission-verdicts.md")
    print("- reports/output/report-v2/executive-report-v2.md")
    print("- reports/output/kai-interface/direct-session.json")
    print("- reports/output/tool-doctor/tool-doctor.md")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
