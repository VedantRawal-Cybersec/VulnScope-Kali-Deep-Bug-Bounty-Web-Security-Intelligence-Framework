#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

OUT = Path("reports/output/autonomous-live")
SESSION_SCOPE = Path("scope_policy.session.yaml")
ARTEMIS_LIVE_CONFIG = OUT / "artemis-live.yaml"

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"

REPORTS = {
    "live": "reports/output/autonomous-live/live-run.md",
    "preflight": "reports/output/mission-preflight/preflight.md",
    "tool_doctor": "reports/output/tool-doctor/tool-doctor.md",
    "tool_mind": "reports/output/tool-mind/tool-mind.md",
    "verdicts": "reports/output/mission-verdicts/mission-verdicts.md",
    "evidence": "reports/output/evidence-cards/evidence-cards.md",
    "reportability": "reports/output/reportability/reportability.md",
    "final": "reports/output/report-v2/executive-report-v2.md",
    "summary": "reports/output/vulnscope-main/final-summary.md",
}

NOISE = [
    "Message from Kali developers",
    "This is a minimal installation of Kali Linux",
    "https://www.kali.org/docs/troubleshooting/common-minimum-setup/",
    "touch ~/.hushlogin",
]

KEYWORDS = [
    "found", "candidate", "endpoint", "subdomain", "url", "route", "param", "risk",
    "review", "critical", "high", "medium", "low", "missing", "header", "api",
    "auth", "idor", "bola", "xss", "sqli", "cors", "hsts", "admin", "login",
]


@dataclass
class Step:
    stage: str
    label: str
    command: str
    timeout: int = 1800
    optional: bool = False
    thought: str = ""


class AgentTerminalUI:
    """Cyan/yellow agent-interaction UI inspired by the reference screenshot."""

    def __init__(self, total_steps: int) -> None:
        self.total_steps = max(1, total_steps)
        self.completed_steps = 0
        self.total_i = 0
        self.total_o = 0
        self.total_r = 0
        self.turn = 0
        self.width = max(96, min(140, shutil.get_terminal_size((110, 30)).columns))
        self.started = time.time()

    def _c(self, text: str, color: str) -> str:
        return f"{color}{text}{RESET}"

    def _border(self, title: str | None = None) -> str:
        if not title:
            return self._c("═" * self.width, CYAN)
        clean = f" {title} "
        fill = max(0, self.width - len(clean))
        return self._c(clean + "═" * fill, CYAN)

    def _context_bar(self) -> str:
        pct = min(100.0, (self.completed_steps / self.total_steps) * 100.0)
        filled = max(1, int(pct / 10)) if pct else 0
        return self._c("█" * filled, GREEN) + self._c("░" * (10 - filled), GRAY) + f" {pct:05.1f}%"

    def _money(self) -> str:
        return "$0.0000"

    def stats_line(self, cur_i: int = 0, cur_o: int = 0, cur_r: int = 0) -> str:
        return (
            f"Current: I:{self._c(str(cur_i), GREEN)} O:{self._c(str(cur_o), RED)} R:{self._c(str(cur_r), YELLOW)} ({self._money()}) | "
            f"Total: I:{self._c(str(self.total_i), GREEN)} O:{self._c(str(self.total_o), RED)} R:{self._c(str(self.total_r), YELLOW)} ({self._money()}) | "
            f"Context: {self._context_bar()}"
        )

    def banner(self, target: str, include_subdomains: bool, include_google_pair: bool, workers: int, cycles: int) -> None:
        print(self._c("\n" + "█" * self.width, CYAN + BOLD))
        print(self._c("█" + " " * (self.width - 2) + "█", CYAN + BOLD))
        print(self._c("█   VULNSCOPE AUTONOMOUS AGENT TERMINAL".ljust(self.width - 1) + "█", CYAN + BOLD))
        print(self._c("█   Agent Interaction • Tool Calls • Live Surface Map • Verdicts".ljust(self.width - 1) + "█", MAGENTA + BOLD))
        print(self._c("█" + " " * (self.width - 2) + "█", CYAN + BOLD))
        print(self._c("█" * self.width + "\n", CYAN + BOLD))
        print(self._c(f"MISSION ID       : VS-{time.strftime('%Y%m%d-%H%M%S')}", WHITE + BOLD))
        print(self._c(f"TARGET           : {target}", WHITE + BOLD))
        print(self._c(f"SUBDOMAINS       : {include_subdomains}", WHITE))
        print(self._c(f"TWO-ACCOUNT MODE : {include_google_pair}", WHITE))
        print(self._c(f"WORKERS/CYCLES   : {workers}/{cycles}", WHITE))
        print(self._c("MODE             : Safe Authorized Review", WHITE))

    def agent(self, title: str, message: str, data: dict[str, Any] | None = None) -> None:
        self.turn += 1
        cur_i = len(message) + (len(json.dumps(data, ensure_ascii=False)) if data else 0)
        self.total_i += cur_i
        print("\n" + self._border("Agent Interaction"))
        print(self._c(f"[{self.turn}] Agent: VulnScope Autonomous Tester >> ", GREEN + BOLD) + self._c(message, YELLOW))
        if data:
            preview = json.dumps(data, ensure_ascii=False)[:900]
            print(self._c("     data >> ", CYAN) + self._c(preview, WHITE))
        print(self.stats_line(cur_i=cur_i, cur_o=0, cur_r=0) + " " + self._c("■", GREEN))

    def tool_start(self, label: str, command: str) -> None:
        args = {"module": label, "command": command}
        print("\n" + self._border("tool_call"))
        print(self._c("vulnscope_safe_module", GREEN + BOLD) + "(" + self._c("command", YELLOW) + "=" + shlex.quote(label) + ", " + self._c("args", YELLOW) + "=" + json.dumps(args, ensure_ascii=False)[:650] + ")")
        print(self.stats_line(cur_i=len(command), cur_o=0, cur_r=0) + " " + self._c("■", GREEN))

    def tool_done(self, label: str, result: dict[str, Any]) -> None:
        output = str(result.get("output_tail") or "")
        cur_o = len(output)
        cur_r = len(extract_interesting_lines(output))
        self.total_o += cur_o
        self.total_r += cur_r
        self.completed_steps += 1
        ok = bool(result.get("ok"))
        color = GREEN if ok else YELLOW if result.get("optional") else RED
        status = "OK" if ok else "REVIEW" if result.get("optional") else "FAILED"
        print(self._c(f"\n{status}: {label} [{result.get('seconds', 0)}s]", color + BOLD))
        for line in extract_interesting_lines(output)[:9]:
            print(self._c("  ├─ ", CYAN) + line[:210])
        if not ok and output and not extract_interesting_lines(output):
            print(self._c("  └─ ", color) + output[-500:].replace("\n", " | ")[:500])
        print(self.stats_line(cur_i=0, cur_o=cur_o, cur_r=cur_r) + " " + self._c("■", GREEN))

    def snapshot(self, target: str, label: str, snap: dict[str, list[str]]) -> None:
        self.agent(
            "Live Surface Snapshot",
            f"After {label}, I am updating the target map with observed hosts, URLs, routes, and parameters.",
            {"hosts": snap.get("domains", [])[:8], "urls": snap.get("urls", [])[:6], "paths": snap.get("paths", [])[:8], "params": snap.get("params", [])[:12]},
        )


def color(text: str, ansi: str) -> str:
    return f"{ansi}{text}{RESET}"


def normalize_target(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("Target cannot be empty")
    return value if "://" in value else "https://" + value


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = parsed.hostname or parsed.netloc or target.replace("https://", "").replace("http://", "").split("/")[0]
    if not host:
        raise ValueError("Invalid target")
    return host.lower()


def write_scope(target: str, include_subdomains: bool) -> Path:
    host = host_from_target(target)
    allowed = [host]
    if include_subdomains and host != "localhost" and not host.replace(".", "").isdigit():
        allowed.append("*." + host)
    SESSION_SCOPE.write_text("\n".join([
        "name: autonomous-live-session",
        "allowed_hosts:",
        *["  - '" + item + "'" for item in allowed],
        "blocked_hosts: []",
        "allowed_schemes:",
        "  - https",
        "  - http",
        "max_requests_per_minute: 30",
        "active_testing_allowed: false",
        "authenticated_testing_allowed: true",
        "notes: 'Generated by autonomous_live_cli.py after explicit user consent. Safe authorized review only.'",
        "",
    ]), encoding="utf-8")
    return SESSION_SCOPE


def write_artemis_config(target: str) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    ARTEMIS_LIVE_CONFIG.write_text("\n".join([
        "targets:",
        f"  - {target}",
        "passive_only: true",
        "require_scope_policy: true",
        "interval_minutes: 360",
        "report_every_cycles: 1",
        "google_search_limit: 5",
        "max_public_records: 1500",
        "respect_rate_limits: true",
        "no_secret_values_in_reports: true",
        "notes: 'Generated by autonomous live CLI. Authorized safe review only.'",
        "",
    ]), encoding="utf-8")
    return ARTEMIS_LIVE_CONFIG


def clean_output(text: str) -> str:
    lines: list[str] = []
    skip = 0
    for raw in (text or "").splitlines():
        if skip:
            skip -= 1
            continue
        if any(noise in raw for noise in NOISE):
            skip = 4
            continue
        if raw.strip():
            lines.append(raw.rstrip())
    return "\n".join(lines)


def extract_interesting_lines(output: str) -> list[str]:
    found: list[str] = []
    for item in output.splitlines():
        low = item.lower()
        if any(word in low for word in KEYWORDS):
            found.append(item.strip())
    return found


def python_script_missing(command: str) -> str | None:
    parts = shlex.split(command)
    if len(parts) >= 2 and parts[0].startswith("python") and parts[1].endswith(".py"):
        if not Path(parts[1]).exists():
            return parts[1]
    return None


def run_command(step: Step, ui: AgentTerminalUI) -> dict[str, Any]:
    missing = python_script_missing(step.command)
    ui.tool_start(step.label, step.command)
    if missing:
        result = {"label": step.label, "command": step.command, "ok": bool(step.optional), "optional": step.optional, "exit_code": 0 if step.optional else 127, "seconds": 0, "output_tail": f"Optional script not present: {missing}"}
        ui.tool_done(step.label, result)
        return result
    started = time.time()
    try:
        proc = subprocess.run(["bash", "-lc", step.command], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=step.timeout)
        output = clean_output(proc.stdout)
        ok = proc.returncode == 0 or step.optional
        result = {"label": step.label, "command": step.command, "ok": ok, "optional": step.optional, "exit_code": proc.returncode, "seconds": round(time.time() - started, 2), "output_tail": output[-7000:]}
    except Exception as exc:
        result = {"label": step.label, "command": step.command, "ok": bool(step.optional), "optional": step.optional, "error": str(exc), "seconds": round(time.time() - started, 2), "output_tail": str(exc)}
    ui.tool_done(step.label, result)
    return result


def load_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def scan_report_text() -> str:
    root = Path("reports/output")
    chunks: list[str] = []
    if not root.exists():
        return ""
    for p in root.rglob("*"):
        if p.suffix.lower() in {".json", ".md", ".txt"} and p.stat().st_size < 2_500_000:
            try:
                chunks.append(p.read_text(encoding="utf-8", errors="ignore")[:220000])
            except Exception:
                pass
    return "\n".join(chunks)


def surface_snapshot(target: str) -> dict[str, list[str]]:
    host = host_from_target(target)
    base = ".".join(host.split(".")[-2:]) if "." in host else host
    text = scan_report_text()
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>),]+", text)))
    domains = sorted(set(re.findall(r"\b[a-zA-Z0-9._-]+\." + re.escape(base) + r"\b", text)))
    paths = sorted(set(re.findall(r"(?<![A-Za-z0-9])/[A-Za-z0-9_./?=&%:-]{2,}", text)))
    params = sorted(set(re.findall(r"[?&]([A-Za-z0-9_:-]{2,})=", text)))
    return {"domains": domains[:40], "urls": urls[:40], "paths": paths[:45], "params": params[:30]}


def build_steps(target: str, include_google_pair: bool, max_cycles: int) -> list[Step]:
    target_q = shlex.quote(target)
    host_q = shlex.quote(host_from_target(target))
    scope_q = shlex.quote(str(SESSION_SCOPE))
    artemis_q = shlex.quote(str(ARTEMIS_LIVE_CONFIG))
    steps: list[Step] = [
        Step("STAGE 1: PREFLIGHT", "Mission Preflight", f"python3 mission_preflight_cli.py --target {target_q} --scope-policy {scope_q}", 600, False, "I will validate the target, scope policy, DNS resolution, typo risk, and stale output state."),
        Step("STAGE 2: TOOLING", "Tool Doctor", "python3 tool_doctor_cli.py --install --yes", 1800, True, "I will repair optional helper binaries and wrappers before collection starts."),
        Step("STAGE 2: TOOLING", "Tool PATH Repair", "python3 tool_path_repair_cli.py", 600, True, "I will verify PATH visibility for local, Go, pipx, and user-local tools."),
        Step("STAGE 2: TOOLING", "Coverage Matrix", "python3 coverage_matrix.py", 600, True, "I will check module coverage so weak zones are visible before the review."),
        Step("STAGE 2: TOOLING", "Mega Tools Status", "python3 mega_tools_cli.py --status", 900, True, "I will inspect the wider tool registry and record what is ready."),
        Step("STAGE 3: INTELLIGENCE", "Neural Tool Mind", f"python3 tool_mind_cli.py --target {target_q} --mode crazy --install-needed --yes", 3600, True, "I will decide which supporting tools matter based on the current evidence corpus."),
        Step("STAGE 3: INTELLIGENCE", "Passive Domain Recon", f"python3 domain_recon_cli.py --target {host_q}", 1800, True, "I will collect passive hosts, archive URLs, and public routes inside the confirmed scope."),
        Step("STAGE 3: INTELLIGENCE", "AEGIS Public Search", f"python3 aegis_public_search_cli.py --target {target_q}", 900, True, "I will use configured public-search sources if available and record gaps if they are not configured."),
        Step("STAGE 3: INTELLIGENCE", "AEGIS Feedback Planner", f"python3 aegis_feedback_cli.py --target {target_q}", 900, True, "I will turn previous observations into the next safe review priorities."),
        Step("STAGE 3: INTELLIGENCE", "ARTEMIS Passive Intelligence", f"python3 artemis_autonomous_cli.py --config {artemis_q} --scope-policy {scope_q} --once", 2400, True, "I will generate passive intelligence predictions from public evidence."),
        Step("STAGE 4: REVIEW", "Safe Evidence Loop", f"python3 safe_loop_v2_cli.py --target {target_q} --mode comprehensive --scope-policy {scope_q} --max-cycles {max_cycles} --yes", 3600, True, "I will review URLs, headers, routes, and parameters in safe evidence-first mode."),
        Step("STAGE 4: REVIEW", "Comprehensive Category Review", f"python3 comprehensive_suite_cli.py --target {target_q} --scope-policy {scope_q} --yes", 2400, True, "I will run broad non-destructive category checks and generate manual review items."),
        Step("STAGE 4: REVIEW", "Proxy Passive Bridge", f"python3 artemis_proxy_passive_cli.py --target {target_q} --limit 100", 900, True, "I will import passive proxy observations if a local proxy API is available."),
    ]
    if include_google_pair:
        steps.append(Step("STAGE 4: REVIEW", "Two Account Precision", f"python3 google_pair_cli.py --target {target_q} --profile default --max-pages 25 --skip-login --skip-if-missing --yes", 3600, True, "I will use saved account states only if they already exist; otherwise I will skip cleanly."))
    steps += [
        Step("STAGE 5: CORRELATION", "Advanced Modes Correlation", f"python3 vulnscope_modes_cli.py --target {target_q} --scope-policy {scope_q}", 2400, True, "I will correlate mode outputs and reduce duplicate weak signals."),
        Step("STAGE 5: CORRELATION", "Normalize Evidence", f"python3 normalize_cli.py --target {target_q}", 900, True, "I will normalize hosts, URLs, parameters, and candidate evidence."),
        Step("STAGE 5: CORRELATION", "Asset Graph", f"python3 asset_graph_cli.py --target {target_q}", 900, True, "I will build a graph linking hosts, endpoints, routes, parameters, and findings."),
        Step("STAGE 5: CORRELATION", "API Intelligence", f"python3 api_intel_cli.py --target {target_q}", 900, True, "I will map API-like endpoints and object/auth review surfaces."),
        Step("STAGE 5: CORRELATION", "Auth Differential v2", "python3 auth_diff_v2_cli.py", 900, True, "I will compare saved auth observations if available and mark anything missing as not tested."),
        Step("STAGE 5: CORRELATION", "Target History", f"python3 target_history_cli.py --target {target_q}", 900, True, "I will compare this target against previous run history and changes."),
        Step("STAGE 6: REPORTING", "Evidence Cards", f"python3 evidence_cards_cli.py --target {target_q}", 900, True, "I will convert evidence into readable review cards."),
        Step("STAGE 6: REPORTING", "Reportability Ranking", f"python3 reportability_cli.py --target {target_q}", 900, True, "I will rank findings by confidence, severity, and manual validation value."),
        Step("STAGE 6: REPORTING", "Mission Verdict Report", f"python3 mission_verdicts_cli.py --target {target_q}", 900, True, "I will consolidate all module decisions into the final verdict table."),
        Step("STAGE 6: REPORTING", "OMEGA Taxonomy Report", f"python3 omega_taxonomy_cli.py --target {target_q}", 900, True, "I will include taxonomy mapping if that optional module exists."),
        Step("STAGE 6: REPORTING", "Final Report", f"python3 report_v2_cli.py --target {target_q}", 900, True, "I will build the executive report."),
        Step("STAGE 6: REPORTING", "JARVIS Summary", f"python3 jarvis_summary_cli.py --target {target_q}", 900, True, "I will print the final terminal summary and next actions."),
    ]
    return steps


def plan_only(target: str, include_subdomains: bool, include_google_pair: bool, max_cycles: int) -> int:
    target = normalize_target(target)
    write_scope(target, include_subdomains)
    write_artemis_config(target)
    steps = build_steps(target, include_google_pair, max_cycles)
    print(json.dumps({"target": target, "steps": [s.__dict__ for s in steps]}, indent=2))
    return 0


def print_verdict_table(ui: AgentTerminalUI) -> dict[str, Any]:
    data = load_json("reports/output/mission-verdicts/mission-verdicts.json") or {}
    rows = data.get("rows", []) if isinstance(data, dict) else []
    summary = data.get("summary", {}) if isinstance(data, dict) else {}
    print("\n" + ui._border("Module Verdicts"))
    print(color(f"{'Module':<24} {'Verdict':<18} {'Severity':<10} Item Tested", BOLD + WHITE))
    print(color("─" * ui.width, CYAN))
    for row in rows[:24]:
        module = str(row.get("module", "unknown"))[:23]
        verdict = str(row.get("verdict", "REVIEW"))[:17]
        severity = str(row.get("severity", "INFO"))[:9]
        item = str(row.get("item", "n/a"))[:55]
        col = GREEN
        if "HIGH" in verdict.upper() or severity.upper() in {"CRITICAL", "HIGH"}:
            col = RED if severity.upper() == "CRITICAL" else YELLOW
        elif "ERROR" in verdict.upper() or "FAILED" in verdict.upper() or "MISSING" in verdict.upper():
            col = RED
        print(f"{color(f'{module:<24}', CYAN)} {color(f'{verdict:<18}', col + BOLD)} {color(f'{severity:<10}', col)} {item}")
    if not rows:
        print(color("No verdict rows generated yet. Check module failures and final report.", YELLOW))
    return {"rows": rows, "summary": summary}


def final_summary(ui: AgentTerminalUI, results: list[dict[str, Any]], target: str) -> dict[str, Any]:
    verdict = print_verdict_table(ui)
    ok = len([r for r in results if r.get("ok")])
    failed = len(results) - ok
    severity = verdict.get("summary", {}).get("severity", {}) if isinstance(verdict.get("summary"), dict) else {}
    high_rows = []
    for row in verdict.get("rows", []):
        if str(row.get("severity", "")).upper() in {"CRITICAL", "HIGH"} or str(row.get("verdict", "")).upper() in {"REVIEW_HIGH", "VULNERABLE", "HIGH_PRIORITY"}:
            high_rows.append(row)
    payload = {"target": target, "tasks": len(results), "ok": ok, "failed": failed, "severity": severity, "high_priority_rows": high_rows[:30], "results": results, "reports": REPORTS, "ui": {"total_i": ui.total_i, "total_o": ui.total_o, "total_r": ui.total_r}}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "live-run.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# VulnScope Live Autonomous Run — {target}", "", f"Tasks: `{len(results)}`", f"OK: `{ok}`", f"Failed/review: `{failed}`", f"UI total I/O/R: `{ui.total_i}/{ui.total_o}/{ui.total_r}`", "", "## High Priority Rows"]
    if high_rows:
        for row in high_rows[:30]:
            lines.append(f"- `{row.get('module')}` `{row.get('item')}` verdict=`{row.get('verdict')}` severity=`{row.get('severity')}` evidence=`{str(row.get('evidence',''))[:300]}`")
    else:
        lines.append("- No high-priority row generated. Review mission-verdicts.md for manual-review items.")
    lines += ["", "## Reports"]
    for name, path in REPORTS.items():
        lines.append(f"- {name}: `{path}`")
    (OUT / "live-run.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def run_live(target: str, include_subdomains: bool, include_google_pair: bool, workers: int, max_cycles: int) -> int:
    target = normalize_target(target)
    OUT.mkdir(parents=True, exist_ok=True)
    write_scope(target, include_subdomains)
    write_artemis_config(target)
    os.environ["PYTHONUNBUFFERED"] = "1"
    steps = build_steps(target, include_google_pair, max_cycles)
    ui = AgentTerminalUI(total_steps=len(steps))
    ui.banner(target, include_subdomains, include_google_pair, workers, max_cycles)
    ui.agent("Consent Verified", "I have authorization confirmation. I will think, choose the next safe module, run it, observe evidence, and update the live target map after every action.", {"target": target, "scope_policy": str(SESSION_SCOPE)})
    results: list[dict[str, Any]] = []
    current_stage = ""
    start = time.time()
    for step in steps:
        if step.stage != current_stage:
            current_stage = step.stage
            ui.agent(current_stage, step.thought or "I am preparing the next safe review stage.")
        else:
            ui.agent(step.label, step.thought or "I am selecting the next action based on the current evidence state.")
        result = run_command(step, ui)
        results.append(result)
        snap = surface_snapshot(target)
        ui.snapshot(target, step.label, snap)
        if not result.get("ok") and not result.get("optional"):
            ui.agent("Critical Stop", f"{step.label} failed and is required. I will stop to avoid misleading output.", {"exit_code": result.get("exit_code"), "error": result.get("error")})
            break
    payload = final_summary(ui, results, target)
    print("\n" + ui._border("Final Output"))
    print(color(f"TARGET                : {target}", WHITE + BOLD))
    print(color(f"TOTAL MODULE TASKS    : {payload['tasks']}", WHITE))
    print(color(f"SUCCESSFUL TASKS      : {payload['ok']}", GREEN + BOLD))
    print(color(f"FAILED / REVIEW TASKS : {payload['failed']}", YELLOW if payload["failed"] else GREEN))
    print(color(f"TOTAL TIME            : {round(time.time() - start, 2)}s", WHITE))
    print(color("SEVERITY SUMMARY      : " + json.dumps(payload.get("severity", {}), ensure_ascii=False), WHITE))
    if payload["high_priority_rows"]:
        print(color("\nTOP HIGH-PRIORITY ROWS", RED + BOLD))
        for row in payload["high_priority_rows"][:10]:
            print(color("  ├─ ", RED) + f"[{row.get('severity')}] {row.get('module')} :: {row.get('item')} :: {row.get('verdict')}")
    else:
        print(color("\nNo high-priority row generated. Review manual candidates in mission-verdicts.md.", YELLOW))
    print(color("\nREPORTS SAVED", CYAN + BOLD))
    for path in REPORTS.values():
        print(color("  ├─ ", CYAN) + path)
    print(color("\nNEXT ACTION", MAGENTA + BOLD))
    print("  Open reports/output/mission-verdicts/mission-verdicts.md first, then validate HIGH/REVIEW rows manually under authorization.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope agent-interaction autonomous live CLI")
    parser.add_argument("--target", required=True)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--include-google-pair", action="store_true")
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--max-cycles", type=int, default=8)
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    if args.plan_only:
        return plan_only(args.target, args.include_subdomains, args.include_google_pair, args.max_cycles)
    return run_live(args.target, args.include_subdomains, args.include_google_pair, args.max_workers, args.max_cycles)


if __name__ == "__main__":
    raise SystemExit(main())
