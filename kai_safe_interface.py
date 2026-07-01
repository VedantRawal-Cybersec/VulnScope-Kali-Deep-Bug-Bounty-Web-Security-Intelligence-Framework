#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from dependency_manager import run_preflight_repair
from live_process_runner import run_visible_command
from scan_dashboard import choose_dashboard
from target_scope_guard import reset_target_report_state

OUT = Path("reports/output/kai-interface")

BANNER = r"""
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║        VULNSCOPE — DIRECT AUTONOMOUS SCAN INTERFACE                ║
║        Target → Consent → Dashboard → Live Engine → Data Bundle     ║
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
    print("This mode asks for a target, locks scope to that target, lets you choose a dashboard, then runs the selected flow.\n")

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


def build_command(session: dict, dashboard: dict) -> list[str]:
    cmd = [
        "python3",
        "autonomous_live_cli.py",
        "--target",
        session["target"],
        "--max-cycles",
        str(dashboard.get("max_cycles", 8)),
        "--max-workers",
        str(dashboard.get("max_workers", 8)),
        "--heartbeat",
        os.getenv("VULNSCOPE_HEARTBEAT", "5"),
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


def run_cai_superior_layer01(session: dict) -> None:
    if os.getenv("VULNSCOPE_SKIP_CAI_SUPERIOR", "0") == "1":
        print("\n[skip] CAI Superior Layer 0–1 skipped by VULNSCOPE_SKIP_CAI_SUPERIOR=1")
        return
    cmd = ["python3", "cai_superior_cli.py", "--target", session["target"]]
    if session.get("include_subdomains"):
        cmd.append("--include-subdomains")
    run_visible_command(
        "CAI Superior Layer 0-1 Target Profile + Passive Recon",
        cmd,
        env=build_scan_env(session),
        timeout=420,
        estimated_seconds=180,
        log_path="reports/output/runtime-logs/cai-superior-layer01.log",
    )


def run_top100_status(session: dict) -> None:
    cmd = ["python3", "top100_integrator_cli.py", "--target", session["target"], "--status"]
    run_visible_command(
        "Top100 Tool Dashboard",
        cmd,
        env=build_scan_env(session),
        timeout=240,
        estimated_seconds=90,
        log_path="reports/output/runtime-logs/top100-status.log",
    )


def run_top100_safe(session: dict, dashboard: dict) -> None:
    cmd = ["python3", "top100_integrator_cli.py", "--target", session["target"], "--run-safe"]
    if dashboard.get("include_controlled_top100"):
        cmd.append("--include-controlled")
    run_visible_command(
        "Top100 Installed Safe Runners",
        cmd,
        env=build_scan_env(session),
        timeout=900,
        estimated_seconds=dashboard.get("estimated_seconds", 600),
        log_path="reports/output/runtime-logs/top100-safe-runners.log",
    )


def run_domain_finding_brief(session: dict) -> None:
    brief_cmd = ["python3", "domain_finding_brief_cli.py", "--target", session["target"]]
    code = run_visible_command(
        "Domain Finding Brief",
        brief_cmd,
        env=build_scan_env(session),
        timeout=240,
        estimated_seconds=60,
        log_path="reports/output/runtime-logs/domain-finding-brief.log",
    )
    slug = domain_slug(session["target"])
    print(f"[+] Finding brief exit code: {code}")
    print(f"[+] Markdown: reports/output/domain-reports/{slug}-finding-brief.md")
    print(f"[+] JSON: reports/output/domain-reports/{slug}-finding-brief.json")


def run_data_bundle(session: dict) -> None:
    cmd = ["python3", "download_data_bundle_cli.py", "--target", session["target"]]
    run_visible_command(
        "Data Bundle Export",
        cmd,
        env=build_scan_env(session),
        timeout=240,
        estimated_seconds=45,
        log_path="reports/output/runtime-logs/data-bundle-export.log",
    )


def run_main_autonomous_scan(session: dict, dashboard: dict) -> int:
    cmd = build_command(session, dashboard)
    return run_visible_command(
        f"Autonomous Website Scan — {dashboard.get('name', 'Selected Dashboard')}",
        cmd,
        env=build_scan_env(session),
        timeout=max(1200, int(dashboard.get("estimated_seconds", 1800)) + 600),
        estimated_seconds=int(dashboard.get("estimated_seconds", 1800)),
        log_path="reports/output/runtime-logs/autonomous-website-scan.log",
    )


def main() -> int:
    session = ask_target_and_consent()

    print("\n[+] Enforcing target isolation for this run")
    isolation = reset_target_report_state(session)
    session["target_isolation"] = isolation
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "direct-session.json").write_text(json.dumps(session, indent=2), encoding="utf-8")
    print(f"[+] Scope locked to: {session['target']} ({session['host']})")
    print(f"[+] Removed stale previous outputs: {len(isolation.get('removed_previous_outputs', []))}")

    run_cai_superior_layer01(session)

    dashboard = choose_dashboard(session)
    session["dashboard"] = dashboard
    (OUT / "direct-session.json").write_text(json.dumps(session, indent=2), encoding="utf-8")

    print("\n[+] Running visible preflight helper-tool check")
    doctor_code = run_preflight_repair(repair=True)
    if doctor_code != 0:
        print("[!] Preflight returned a non-zero exit code. Continuing because helper tools are optional.")

    run_top100_status(session)

    code = 0
    if dashboard.get("run_main_scan", True):
        code = run_main_autonomous_scan(session, dashboard)
    else:
        print(f"\n[+] Main autonomous scan skipped by dashboard profile: {dashboard.get('profile')}")

    if dashboard.get("run_top100_safe", False):
        run_top100_safe(session, dashboard)

    run_domain_finding_brief(session)
    run_data_bundle(session)

    slug = domain_slug(session["target"])
    if code == 0:
        print("\n[+] Selected flow finished successfully. Open these reports:")
    else:
        print(f"\n[!] Selected flow exited with code {code}. Open the logs below to see the exact failing module:")
    print("- reports/output/kai-interface/scan-dashboard-selection.md")
    print("- reports/output/cai-superior/{}/cai-superior-summary.md".format(slug))
    print("- reports/output/cai-superior/{}/target-profile.md".format(slug))
    print("- reports/output/cai-superior/{}/recon-agent.md".format(slug))
    print("- reports/output/cai-superior/{}/asset-graph.md".format(slug))
    print("- reports/output/autonomous-live/live-run.md")
    print("- reports/output/autonomous-live/live-run.json")
    print("- reports/output/vulnscope-main/final-summary.md")
    print("- reports/output/mission-verdicts/mission-verdicts.md")
    print("- reports/output/report-v2/executive-report-v2.md")
    print(f"- reports/output/domain-reports/{slug}-finding-brief.md")
    print("- reports/output/top100-tools/top100-status.md")
    print(f"- reports/output/top100-tools/{slug}/top100-integration.md")
    print(f"- reports/output/download-bundles/{slug}-latest-data-bundle.zip")
    print("- reports/output/runtime-logs/")
    print("- reports/output/kai-interface/direct-session.json")
    print("- reports/output/current-target-session.json")
    print("- reports/output/tool-doctor/tool-doctor.md")
    print("- reports/output/tool-doctor/tool-doctor-install.log")
    return int(code)


if __name__ == "__main__":
    raise SystemExit(main())
