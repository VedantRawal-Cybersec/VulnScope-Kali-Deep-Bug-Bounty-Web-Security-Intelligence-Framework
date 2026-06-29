#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

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
[1] AI Autonomous Full Review          Target -> Confirm -> Tool Mind -> Think -> Run -> Correlate -> Report
[2] Daily Tool Repair / Update         Install missing tools, update templates, fix PATH issues
[3] AI Tool Mind Healthcheck           Think what tools are needed, install missing supported tools
[4] Passive Domain Recon               Subdomains, archived URLs, high-value routes
[5] Comprehensive Category Review      XSS/IDOR/SQLi/API/Auth/CORS/GraphQL/etc. review candidates
[6] Google Auth Context Review         Review saved Google/OAuth session evidence safely
[7] Report Builder                     Generate final executive + technical report
[8] Show Last AI Decision Plan          See what the engine decided and why
[9] Show Last Final Report              Open final Markdown report
[10] Coverage Matrix                   Prove category/module coverage counts
[11] Repo Health / Error Check          Compile check, dependency check, CLI smoke tests
[12] Mega Tools 50+ Installer/Status    Best-effort install/status for large safe tool registry
[13] Evidence Cards                    What/where/why/how-to-check cards from collected findings
[14] Advanced Modes Orchestrator        Normalize -> Graph -> Tool Brain -> API -> Diff -> Reportability
[15] Asset Graph                        Unified host/endpoint/param/finding graph
[16] API Intelligence                   API, GraphQL, object-auth and mutation surface mapping
[17] Account A/B Differential v2        Deeper owned-account comparison review
[18] Reportability Ranking              Rank candidates by evidence strength
[19] Target History / Diff              Track new endpoints, params, findings over time
[20] Two Google Account Precision       Google A/B login, crawl, compare, diff, evidence cards
[21] Neural Tool Mind / Auto Installer  Human-like tool reasoning + install/repair plan
[22] Tool PATH Repair                   Fix installed-but-not-found binaries and shell PATH
[23] JARVIS Run Summary                 Show findings, why flagged, and next actions inline
[24] AEGIS-SAFE Full Mode               Non-destructive autonomous safe review pipeline
[25] AEGIS Public Search Intel          Google Custom Search OSINT candidates, redacted
[26] AEGIS Feedback Planner             PID-style next-action planning from weak/strong evidence
[27] ARTEMIS Passive Autonomous         24/7 passive recon + ML-style prediction + reports
[28] ARTEMIS Web Dashboard              Local passive intelligence dashboard on port 8080
[29] ARTEMIS Init Config                Create artemis_config.yaml example
[30] ARTEMIS Proxy Passive Bridge       Scope seeds + passive finding import, no active tests
[0] Exit
"""

SAFE_COMMAND_PREFIXES = (
    "python3 coverage_matrix.py", "python3 daily_update_cli.py", "python3 auto_mode.py",
    "python3 domain_recon_cli.py", "python3 autopilot_cli.py", "python3 comprehensive_suite_cli.py",
    "python3 google_context_cli.py", "python3 report_v2_cli.py", "python3 safe_loop_v2_cli.py",
    "python3 repo_health_cli.py", "python3 mega_tools_cli.py", "python3 evidence_cards_cli.py",
    "python3 normalize_cli.py", "python3 asset_graph_cli.py", "python3 tool_brain_cli.py",
    "python3 tool_mind_cli.py", "python3 tool_path_repair_cli.py", "python3 jarvis_summary_cli.py",
    "python3 api_intel_cli.py", "python3 auth_diff_v2_cli.py", "python3 reportability_cli.py",
    "python3 target_history_cli.py", "python3 vulnscope_modes_cli.py", "python3 google_pair_cli.py",
    "python3 safe_aegis_cli.py", "python3 aegis_public_search_cli.py", "python3 aegis_feedback_cli.py",
    "python3 artemis_autonomous_cli.py", "python3 artemis_dashboard.py", "python3 artemis_proxy_passive_cli.py", "cat reports/output/",
)


def clear() -> None:
    os.system("clear" if os.name == "posix" else "cls")


def pause() -> None:
    input("\nPress Enter to continue...")


def normalize_target(target: str) -> str:
    if not target.strip():
        raise ValueError("Target cannot be empty")
    return target.strip() if "://" in target else "https://" + target.strip()


def target_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else "https://" + target)
    host = parsed.netloc.split(":")[0].strip().lower()
    if not host:
        raise ValueError("Invalid target. Use a URL or domain, for example https://example.com")
    return host


def create_session_scope(target: str, include_subdomains: bool) -> Path:
    target = normalize_target(target)
    host = target_host(target)
    allowed = [host]
    if include_subdomains and host not in {"localhost"} and not host.replace(".", "").isdigit():
        allowed.append("*." + host)
    lines = [
        "name: vulnscope-confirmed-session", "allowed_hosts:", *[f"  - '{item}'" for item in allowed],
        "blocked_hosts: []", "allowed_schemes:", "  - https", "  - http", "max_requests_per_minute: 30",
        "active_testing_allowed: false", "authenticated_testing_allowed: true",
        "notes: 'Generated from VulnScope CLI after explicit user authorization confirmation. Safe evidence review only.'", "",
    ]
    SESSION_SCOPE.write_text("\n".join(lines), encoding="utf-8")
    AUTH_OUT.mkdir(parents=True, exist_ok=True)
    audit = {
        "target": target, "host": host, "include_subdomains": include_subdomains,
        "confirmed_authorization": True, "confirmed_at": datetime.now(timezone.utc).isoformat(),
        "session_scope": str(SESSION_SCOPE),
        "rules": {"safe_evidence_review": True, "no_state_changing_actions": True, "no_credential_collection": True, "no_data_extraction": True},
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


def optional_target_label() -> str:
    raw = input("Target URL/domain label (blank = use existing evidence only): ").strip()
    return normalize_target(raw) if raw else ""


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
    use_google_pair = input("Run two-Google-account precision workflow if saved/login available? yes/no: ").strip().lower() in {"y", "yes"}
    use_proxy = input("Run ARTEMIS Proxy Passive Bridge if local API is available? yes/no: ").strip().lower() in {"y", "yes"}
    commands = [
        ("Neural coverage map", "python3 coverage_matrix.py", "5-15s"),
        ("Neural tool mind", f"python3 tool_mind_cli.py --target {target} --mode crazy --install-needed --yes", "1-30 min"),
        ("Tool path repair", "python3 tool_path_repair_cli.py", "5-20s"),
        ("AEGIS public search", f"python3 aegis_public_search_cli.py --target {target}", "5-30s"),
        ("AEGIS feedback planner", f"python3 aegis_feedback_cli.py --target {target}", "5-20s"),
        ("ARTEMIS passive intelligence", f"python3 artemis_autonomous_cli.py --config artemis_config.yaml --scope-policy {scope} --once", "30s-5 min"),
    ]
    if use_proxy:
        commands.append(("ARTEMIS Proxy Passive Bridge", f"python3 artemis_proxy_passive_cli.py --target {target} --limit 80", "5-30s"))
    commands += [
        ("Mega tools status", "python3 mega_tools_cli.py --status", "10-30s"),
        ("Daily repair/update", "python3 daily_update_cli.py --profile bug-bounty-safe --yes", "1-5 min"),
        ("Autonomous evidence loop", f"python3 safe_loop_v2_cli.py --target {target} --mode comprehensive --scope-policy {scope} --max-cycles {max_cycles} --yes" + (f" --provider {provider}" if provider else ""), "5-30 min"),
        ("Comprehensive category review", f"python3 comprehensive_suite_cli.py --target {target} --scope-policy {scope} --yes", "30s-3 min"),
        ("Google/OAuth context review", "python3 google_context_cli.py", "5-30s"),
    ]
    if use_google_pair:
        commands.append(("Two Google Account Precision", f"python3 google_pair_cli.py --target {target} --profile default --max-pages 25 --yes", "5-30 min"))
    commands += [
        ("Advanced modes correlation", f"python3 vulnscope_modes_cli.py --target {target} --scope-policy {scope}", "30s-5 min"),
        ("Evidence cards", f"python3 evidence_cards_cli.py --target {target}", "5-30s"),
        ("Final report", f"python3 report_v2_cli.py --target {target}", "5-30s"),
        ("JARVIS summary", f"python3 jarvis_summary_cli.py --target {target}", "instant"),
    ]
    history = [run_step(label, cmd, est) for label, cmd, est in commands]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "interactive-full-review.json").write_text(json.dumps({"target": target, "scope": scope, "history": history}, indent=2), encoding="utf-8")
    print("\n[+] Full review complete.")
    print("[+] Run history: reports/output/cli/interactive-full-review.json")
    print("[+] ARTEMIS: reports/output/artemis/run/artemis-run.md")
    print("[+] Proxy Passive Bridge: reports/output/artemis/burp-safe/burp-safe.md")
    print("[+] AEGIS feedback: reports/output/aegis/feedback/feedback-plan.md")
    print("[+] Evidence cards: reports/output/evidence-cards/evidence-cards.md")
    print("[+] Final report: reports/output/report-v2/executive-report-v2.md")


def menu_loop() -> None:
    while True:
        clear(); print(BANNER); print(MENU)
        choice = input("Select option: ").strip()
        try:
            if choice == "1": ai_full_review()
            elif choice == "2": run_step("Daily repair/update", "python3 daily_update_cli.py --profile bug-bounty-safe --force --yes", "1-5 min")
            elif choice == "3":
                target = optional_target_label(); cmd = "python3 tool_mind_cli.py --mode deep --install-needed --yes" + (f" --target {target}" if target else ""); run_step("AI Tool Mind Healthcheck", cmd, "1-30 min")
            elif choice == "4": target, _ = ask_target_and_scope(); run_step("Passive recon", f"python3 domain_recon_cli.py --target {target_host(target)}", "1-5 min")
            elif choice == "5": target, scope = ask_target_and_scope(); run_step("Comprehensive category review", f"python3 comprehensive_suite_cli.py --target {target} --scope-policy {scope} --yes", "30s-3 min")
            elif choice == "6": run_step("Google context review", "python3 google_context_cli.py", "5-30s")
            elif choice == "7": target = normalize_target(input("Target for report label: ").strip()); run_step("Report builder", f"python3 report_v2_cli.py --target {target}", "5-30s")
            elif choice == "8": run_step("Show decision plan", "cat reports/output/autonomy/decision-plan.md", "instant")
            elif choice == "9": run_step("Show final report", "cat reports/output/report-v2/executive-report-v2.md", "instant")
            elif choice == "10": run_step("Coverage matrix", "python3 coverage_matrix.py", "5-15s")
            elif choice == "11": run_step("Repo health", "python3 repo_health_cli.py --install-python-deps --tool-update", "1-10 min")
            elif choice == "12": install = input("Install missing supported mega tools? yes/no: ").strip().lower() in {"y", "yes"}; run_step("Mega tools", "python3 mega_tools_cli.py --install-missing --yes" if install else "python3 mega_tools_cli.py --status", "10s-30 min")
            elif choice == "13": target = normalize_target(input("Target label for evidence cards: ").strip()); run_step("Evidence cards", f"python3 evidence_cards_cli.py --target {target}", "5-30s")
            elif choice == "14": target, scope = ask_target_and_scope(); run_step("Advanced modes", f"python3 vulnscope_modes_cli.py --target {target} --scope-policy {scope}", "30s-5 min")
            elif choice == "15": target = normalize_target(input("Target label: ").strip()); run_step("Asset graph", f"python3 asset_graph_cli.py --target {target}", "5-30s")
            elif choice == "16": target = normalize_target(input("Target label: ").strip()); run_step("API intelligence", f"python3 api_intel_cli.py --target {target}", "5-30s")
            elif choice == "17": run_step("Auth differential v2", "python3 auth_diff_v2_cli.py", "5-30s")
            elif choice == "18": target = normalize_target(input("Target label: ").strip()); run_step("Reportability", f"python3 reportability_cli.py --target {target}", "5-30s")
            elif choice == "19": target = normalize_target(input("Target label: ").strip()); run_step("Target history", f"python3 target_history_cli.py --target {target}", "5-30s")
            elif choice == "20":
                target, _ = ask_target_and_scope(); skip = input("Use existing saved Google login states and skip login? yes/no: ").strip().lower() in {"y", "yes"}; max_pages = input("Max pages per account [25]: ").strip() or "25"; cmd = f"python3 google_pair_cli.py --target {target} --profile default --max-pages {max_pages} --yes" + (" --skip-login" if skip else ""); run_step("Two Google Account Precision", cmd, "5-30 min")
            elif choice == "21":
                target = optional_target_label(); mode = input("Tool mind mode [deep/base/full/crazy]: ").strip() or "deep"; install = input("Install missing needed tools? yes/no: ").strip().lower() in {"y", "yes"}; cmd = f"python3 tool_mind_cli.py --mode {mode}" + (f" --target {target}" if target else "") + (" --install-needed --yes" if install else ""); run_step("Neural Tool Mind", cmd, "10s-30 min")
            elif choice == "22": run_step("Tool PATH Repair", "python3 tool_path_repair_cli.py", "5-20s")
            elif choice == "23": target = input("Target label for summary (blank = authorized target): ").strip() or "authorized target"; run_step("JARVIS Run Summary", f"python3 jarvis_summary_cli.py --target {target}", "instant")
            elif choice == "24": target, scope = ask_target_and_scope(); cycles = input("AEGIS cycles [8]: ").strip() or "8"; run_step("AEGIS-SAFE Full Mode", f"python3 safe_aegis_cli.py --target {target} --scope-policy {scope} --cycles {cycles} --yes", "5-45 min")
            elif choice == "25": target = normalize_target(input("Target URL/domain: ").strip()); run_step("AEGIS Public Search Intel", f"python3 aegis_public_search_cli.py --target {target}", "5-30s")
            elif choice == "26": target = normalize_target(input("Target URL/domain: ").strip()); run_step("AEGIS Feedback Planner", f"python3 aegis_feedback_cli.py --target {target}", "5-20s")
            elif choice == "27": run_step("ARTEMIS Passive Autonomous", "python3 artemis_autonomous_cli.py --config artemis_config.yaml --scope-policy scope_policy.yaml --once", "30s-5 min")
            elif choice == "28": run_step("ARTEMIS Web Dashboard", "python3 artemis_dashboard.py", "runs until Ctrl+C")
            elif choice == "29": run_step("ARTEMIS Init Config", "python3 artemis_autonomous_cli.py --init-config --config artemis_config.yaml", "instant")
            elif choice == "30": target = optional_target_label(); run_step("ARTEMIS Proxy Passive Bridge", "python3 artemis_proxy_passive_cli.py" + (f" --target {target}" if target else ""), "5-30s")
            elif choice == "0": print("Goodbye."); return
            else: print("Invalid option.")
        except Exception as exc:
            print(f"\n[!] {exc}")
        pause()


def main() -> int:
    menu_loop(); return 0


if __name__ == "__main__":
    raise SystemExit(main())
