#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

APP = "VulnScope AI"
OUT = Path("reports/output/cli")
AUTH_OUT = Path("reports/output/authorization")
SESSION_SCOPE = Path("scope_policy.session.yaml")

BANNER = r"""
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ██║   ██║██████╔╝█████╗  
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
                       AI AUTONOMOUS WEB SECURITY REVIEW
"""

MENU = """
[1] AI Autonomous Full Review          Target -> Confirm -> Think -> Run -> Report
[2] Daily Tool Repair / Update         Install missing tools, update templates, fix PATH issues
[3] Tool Healthcheck                   Check installed/missing tool state
[4] Passive Domain Recon               Subdomains, archived URLs, high-value routes
[5] Comprehensive Category Review      XSS/IDOR/SQLi/API/Auth/CORS/GraphQL/etc. review candidates
[6] Google Auth Context Review         Review saved Google/OAuth session evidence safely
[7] Report Builder                     Generate final executive + technical report
[8] Show Last AI Decision Plan          See what the engine decided and why
[9] Show Last Final Report              Open final Markdown report
[10] Coverage Matrix                   Prove category/module coverage counts
[11] Repo Health / Error Check          Compile check, dependency check, CLI smoke tests
[0] Exit
"""

SAFE_COMMAND_PREFIXES = (
    "python3 coverage_matrix.py",
    "python3 daily_update_cli.py",
    "python3 auto_mode.py",
    "python3 domain_recon_cli.py",
    "python3 autopilot_cli.py",
    "python3 comprehensive_suite_cli.py",
    "python3 google_context_cli.py",
    "python3 report_v2_cli.py",
    "python3 safe_loop_v2_cli.py",
    "python3 repo_health_cli.py",
    "cat reports/output/",
)


def clear() -> None:
    os.system("clear" if os.name == "posix" else "cls")


def pause() -> None:
    input("\nPress Enter to continue...")


def target_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else "https://" + target)
    host = parsed.netloc.split(":")[0].strip().lower()
    if not host:
        raise ValueError("Invalid target. Use a URL or domain, for example https://example.com")
    return host


def normalize_target(target: str) -> str:
    if not target.strip():
        raise ValueError("Target cannot be empty")
    return target.strip() if "://" in target else "https://" + target.strip()


def create_session_scope(target: str, include_subdomains: bool) -> Path:
    target = normalize_target(target)
    host = target_host(target)
    allowed = [host]
    if include_subdomains and host not in {"localhost"} and not host.replace(".", "").isdigit():
        allowed.append("*." + host)
    lines = [
        "name: vulnscope-confirmed-session",
        "allowed_hosts:",
        *[f"  - '{item}'" for item in allowed],
        "blocked_hosts: []",
        "allowed_schemes:",
        "  - https",
        "  - http",
        "max_requests_per_minute: 30",
        "active_testing_allowed: false",
        "authenticated_testing_allowed: true",
        "notes: 'Generated from VulnScope CLI after explicit user authorization confirmation. Safe evidence review only.'",
        "",
    ]
    SESSION_SCOPE.write_text("\n".join(lines), encoding="utf-8")
    AUTH_OUT.mkdir(parents=True, exist_ok=True)
    audit = {
        "target": target,
        "host": host,
        "include_subdomains": include_subdomains,
        "confirmed_authorization": True,
        "confirmed_at": datetime.now(timezone.utc).isoformat(),
        "session_scope": str(SESSION_SCOPE),
        "rules": {
            "safe_evidence_review": True,
            "no_state_changing_actions": True,
            "no_credential_collection": True,
            "no_data_extraction": True,
        },
    }
    (AUTH_OUT / "cli-session-confirmation.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    return SESSION_SCOPE


def ask_target_and_scope() -> tuple[str, str]:
    target = normalize_target(input("\nEnter target URL/domain: ").strip())
    print("\nAuthorization confirmation required.")
    print("Run this only for a website or bug-bounty asset you own or are explicitly allowed to test.")
    ans = input(f"Do you confirm authorization for {target}? type YES: ").strip()
    if ans != "YES":
        raise RuntimeError("Authorization not confirmed. Session cancelled.")
    sub = input("Include subdomains in this session? yes/no: ").strip().lower() in {"y", "yes"}
    scope = create_session_scope(target, sub)
    print(f"\n[+] Session scope created: {scope}")
    print("[+] Authorization audit: reports/output/authorization/cli-session-confirmation.json")
    return target, str(scope)


def safe_command(command: str) -> bool:
    stripped = command.strip()
    forbidden = [";", "| sh", "bash -i", " nc ", " ncat ", "rm -rf", "curl ", "wget "]
    return stripped.startswith(SAFE_COMMAND_PREFIXES) and not any(x in stripped for x in forbidden)


def run_step(label: str, command: str, estimate: str = "varies") -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"\n┌─[ {label} ]")
    print(f"├─ Estimate : {estimate}")
    print(f"├─ Command  : {command}")
    if not safe_command(command):
        print("└─ Blocked  : command is not in VulnScope CLI allowlist")
        return {"label": label, "command": command, "ok": False, "reason": "not allowlisted"}
    started = time.time()
    proc = subprocess.Popen(["bash", "-lc", command], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    output_lines: list[str] = []
    spinner = ["◐", "◓", "◑", "◒"]
    tick = 0
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip()
        output_lines.append(line)
        if line:
            print(f"│ {spinner[tick % len(spinner)]} {line[:160]}")
            tick += 1
    code = proc.wait()
    seconds = round(time.time() - started, 2)
    status = "OK" if code == 0 else "FAILED"
    print(f"└─ {status} in {seconds}s")
    return {"label": label, "command": command, "ok": code == 0, "exit_code": code, "seconds": seconds, "tail": "\n".join(output_lines[-40:])}


def ai_full_review() -> None:
    target, scope = ask_target_and_scope()
    provider = input("AI provider (blank to skip, e.g. anthropic/openai): ").strip() or None
    max_cycles = input("Max thinking cycles [8]: ").strip() or "8"
    commands = [
        ("Neural coverage map", "python3 coverage_matrix.py", "5-15s"),
        ("Daily repair/update", "python3 daily_update_cli.py --profile bug-bounty-safe --yes", "1-5 min"),
        ("Autonomous evidence loop", f"python3 safe_loop_v2_cli.py --target {target} --mode comprehensive --scope-policy {scope} --max-cycles {max_cycles} --yes" + (f" --provider {provider}" if provider else ""), "5-30 min"),
        ("Comprehensive category review", f"python3 comprehensive_suite_cli.py --target {target} --scope-policy {scope} --yes", "30s-3 min"),
        ("Google/OAuth context review", "python3 google_context_cli.py", "5-30s"),
        ("Final report", f"python3 report_v2_cli.py --target {target}", "5-30s"),
    ]
    history = []
    for label, cmd, est in commands:
        history.append(run_step(label, cmd, est))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "interactive-full-review.json").write_text(json.dumps({"target": target, "scope": scope, "history": history}, indent=2), encoding="utf-8")
    print("\n[+] Full review complete.")
    print("[+] Run history: reports/output/cli/interactive-full-review.json")
    print("[+] Final report: reports/output/report-v2/executive-report-v2.md")


def menu_loop() -> None:
    while True:
        clear()
        print(BANNER)
        print(MENU)
        choice = input("Select option: ").strip()
        try:
            if choice == "1":
                ai_full_review()
            elif choice == "2":
                run_step("Daily repair/update", "python3 daily_update_cli.py --profile bug-bounty-safe --force --yes", "1-5 min")
            elif choice == "3":
                run_step("Healthcheck", "python3 auto_mode.py --profile bug-bounty-safe --healthcheck", "5-20s")
            elif choice == "4":
                target, _ = ask_target_and_scope()
                run_step("Passive recon", f"python3 domain_recon_cli.py --target {target_host(target)}", "1-5 min")
            elif choice == "5":
                target, scope = ask_target_and_scope()
                run_step("Comprehensive category review", f"python3 comprehensive_suite_cli.py --target {target} --scope-policy {scope} --yes", "30s-3 min")
            elif choice == "6":
                run_step("Google context review", "python3 google_context_cli.py", "5-30s")
            elif choice == "7":
                target = normalize_target(input("Target for report label: ").strip())
                run_step("Report builder", f"python3 report_v2_cli.py --target {target}", "5-30s")
            elif choice == "8":
                run_step("Show decision plan", "cat reports/output/autonomy/decision-plan.md", "instant")
            elif choice == "9":
                run_step("Show final report", "cat reports/output/report-v2/executive-report-v2.md", "instant")
            elif choice == "10":
                run_step("Coverage matrix", "python3 coverage_matrix.py", "5-15s")
            elif choice == "11":
                run_step("Repo health", "python3 repo_health_cli.py --install-python-deps --tool-update", "1-10 min")
            elif choice == "0":
                print("Goodbye.")
                return
            else:
                print("Invalid option.")
        except Exception as exc:
            print(f"\n[!] {exc}")
        pause()


def main() -> int:
    menu_loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
