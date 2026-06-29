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
CURRENT_TARGET_FILE = Path("reports/output/current-target-session.json")

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

TARGET_OUTPUT_DIRS = [
    "reports/output/mission-preflight",
    "reports/output/domain-recon",
    "reports/output/aegis-public-search",
    "reports/output/aegis-feedback",
    "reports/output/artemis",
    "reports/output/proxy-passive",
    "reports/output/google-pair",
    "reports/output/google-context",
    "reports/output/safe-loop-v2",
    "reports/output/comprehensive-suite",
    "reports/output/vulnscope-modes",
    "reports/output/normalized",
    "reports/output/asset-graph",
    "reports/output/api-intel",
    "reports/output/auth-diff-v2",
    "reports/output/target-history",
    "reports/output/evidence-cards",
    "reports/output/reportability",
    "reports/output/mission-verdicts",
    "reports/output/report-v2",
    "reports/output/vulnscope-main",
    "reports/output/canary-review-matrix",
    "reports/output/precision-assurance",
]

KEYWORDS = [
    "found", "candidate", "endpoint", "subdomain", "url", "route", "param", "risk", "review",
    "critical", "high", "medium", "low", "missing", "header", "api", "auth", "cors", "hsts", "admin", "login",
]

NOISE = [
    "Message from Kali developers",
    "This is a minimal installation of Kali Linux",
    "https://www.kali.org/docs/troubleshooting/common-minimum-setup/",
    "touch ~/.hushlogin",
]

BIG_LOGO = r"""
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ██║   ██║██████╔╝█████╗  
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
"""


@dataclass
class Step:
    stage: str
    label: str
    command: str
    thought: str
    timeout: int = 1800
    optional: bool = True


class AgentTerminalUI:
    def __init__(self, total_steps: int) -> None:
        self.total_steps = max(1, total_steps)
        self.done = 0
        self.turn = 0
        self.total_i = 0
        self.total_o = 0
        self.total_r = 0
        self.width = max(110, min(150, shutil.get_terminal_size((120, 30)).columns))

    def c(self, text: str, color: str) -> str:
        return f"{color}{text}{RESET}"

    def border(self, title: str) -> str:
        label = f" {title} "
        return self.c(label + "═" * max(0, self.width - len(label)), CYAN)

    def context(self) -> str:
        pct = min(100.0, (self.done / self.total_steps) * 100.0)
        bars = int(pct / 10)
        return self.c("█" * bars, GREEN) + self.c("░" * (10 - bars), GRAY) + f" {pct:05.1f}%"

    def stats(self, i: int = 0, o: int = 0, r: int = 0) -> str:
        return (
            f"Current: I:{self.c(str(i), GREEN)} O:{self.c(str(o), RED)} R:{self.c(str(r), YELLOW)} ($0.0000) | "
            f"Total: I:{self.c(str(self.total_i), GREEN)} O:{self.c(str(self.total_o), RED)} R:{self.c(str(self.total_r), YELLOW)} ($0.0000) | "
            f"Context: {self.context()} {self.c('■', GREEN)}"
        )

    def banner(self, target: str, include_subdomains: bool, two_account: bool, workers: int, cycles: int) -> None:
        print(self.c("\n" + "█" * self.width, CYAN + BOLD))
        for line in BIG_LOGO.strip("\n").splitlines():
            pad = max(0, self.width - len(line) - 2)
            print(self.c("█ " + line + " " * pad + "█", CYAN + BOLD))
        print(self.c("█" + " " * (self.width - 2) + "█", CYAN + BOLD))
        title = "VULNSCOPE AUTONOMOUS AGENT TOOL"
        sub = "Agent Interaction • Live Tool Calls • Surface Map • Target-Isolated Reports • Final Verdicts"
        print(self.c("█ " + title.center(self.width - 4) + " █", MAGENTA + BOLD))
        print(self.c("█ " + sub.center(self.width - 4) + " █", YELLOW + BOLD))
        print(self.c("█" * self.width + "\n", CYAN + BOLD))
        print(self.c(f"MISSION ID       : VS-{time.strftime('%Y%m%d-%H%M%S')}", WHITE + BOLD))
        print(self.c(f"TARGET           : {target}", WHITE + BOLD))
        print(self.c(f"SUBDOMAINS       : {include_subdomains}", WHITE))
        print(self.c(f"TWO-ACCOUNT MODE : {two_account}", WHITE))
        print(self.c(f"WORKERS/CYCLES   : {workers}/{cycles}", WHITE))
        print(self.c("MODE             : Safe Authorized Review", WHITE))

    def agent(self, message: str, data: dict[str, Any] | None = None) -> None:
        self.turn += 1
        raw_data = json.dumps(data, ensure_ascii=False) if data else ""
        cur_i = len(message) + len(raw_data)
        self.total_i += cur_i
        print("\n" + self.border("Agent Interaction"))
        print(self.c(f"[{self.turn}] Agent: VulnScope Autonomous Tester >> ", GREEN + BOLD) + self.c(message, YELLOW))
        if data:
            print(self.c("     data >> ", CYAN) + self.c(raw_data[:1000], WHITE))
        print(self.stats(i=cur_i))

    def tool_start(self, step: Step) -> None:
        args = {"module": step.label, "stage": step.stage, "command": step.command}
        print("\n" + self.border("tool_call"))
        print(self.c("vulnscope_safe_module", GREEN + BOLD) + "(" + self.c("command", YELLOW) + "=" + shlex.quote(step.label) + ", " + self.c("args", YELLOW) + "=" + json.dumps(args, ensure_ascii=False)[:850] + ")")
        print(self.stats(i=len(step.command)))

    def tool_done(self, result: dict[str, Any]) -> None:
        output = str(result.get("output_tail") or "")
        cur_o = len(output)
        cur_r = len(extract_interesting_lines(output))
        self.total_o += cur_o
        self.total_r += cur_r
        self.done += 1
        ok = bool(result.get("ok"))
        col = GREEN if ok else YELLOW if result.get("optional") else RED
        status = "OK" if ok else "REVIEW" if result.get("optional") else "FAILED"
        print(self.c(f"\n{status}: {result.get('label')} [{result.get('seconds', 0)}s]", col + BOLD))
        for item in extract_interesting_lines(output)[:10]:
            print(self.c("  ├─ ", CYAN) + item[:220])
        if output and not extract_interesting_lines(output) and not ok:
            print(self.c("  └─ ", col) + output[-600:].replace("\n", " | ")[:600])
        print(self.stats(o=cur_o, r=cur_r))


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


def reset_target_outputs(target: str) -> dict[str, Any]:
    """Remove previous target-dependent reports so a new user URL cannot reuse old findings."""
    target = normalize_target(target)
    host = host_from_target(target)
    removed: list[str] = []
    for raw in TARGET_OUTPUT_DIRS:
        p = Path(raw)
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
            removed.append(str(p))
    CURRENT_TARGET_FILE.parent.mkdir(parents=True, exist_ok=True)
    CURRENT_TARGET_FILE.write_text(json.dumps({"target": target, "host": host, "started_at": time.time(), "removed_output_dirs": removed}, indent=2), encoding="utf-8")
    return {"target": target, "host": host, "removed_dirs": removed}


def write_scope(target: str, include_subdomains: bool) -> None:
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


def write_artemis_config(target: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    ARTEMIS_LIVE_CONFIG.write_text("\n".join([
        "targets:", f"  - {target}", "passive_only: true", "require_scope_policy: true",
        "interval_minutes: 360", "report_every_cycles: 1", "google_search_limit: 5",
        "max_public_records: 1500", "respect_rate_limits: true", "no_secret_values_in_reports: true", "",
    ]), encoding="utf-8")


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
    rows: list[str] = []
    for item in output.splitlines():
        low = item.lower()
        if any(k in low for k in KEYWORDS):
            rows.append(item.strip())
    return rows


def script_missing(command: str) -> str | None:
    parts = shlex.split(command)
    if len(parts) >= 2 and parts[0].startswith("python") and parts[1].endswith(".py") and not Path(parts[1]).exists():
        return parts[1]
    return None


def run_step(step: Step, ui: AgentTerminalUI) -> dict[str, Any]:
    ui.tool_start(step)
    missing = script_missing(step.command)
    if missing:
        result = {"label": step.label, "command": step.command, "ok": bool(step.optional), "optional": step.optional, "exit_code": 0 if step.optional else 127, "seconds": 0, "output_tail": f"Optional script not present: {missing}"}
        ui.tool_done(result)
        return result
    started = time.time()
    try:
        proc = subprocess.run(["bash", "-lc", step.command], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=step.timeout)
        output = clean_output(proc.stdout)
        result = {"label": step.label, "stage": step.stage, "command": step.command, "ok": proc.returncode == 0 or step.optional, "optional": step.optional, "exit_code": proc.returncode, "seconds": round(time.time() - started, 2), "output_tail": output[-8000:]}
    except Exception as exc:
        result = {"label": step.label, "stage": step.stage, "command": step.command, "ok": bool(step.optional), "optional": step.optional, "error": str(exc), "seconds": round(time.time() - started, 2), "output_tail": str(exc)}
    ui.tool_done(result)
    return result


def scan_report_text(target: str) -> str:
    host = host_from_target(target)
    root = Path("reports/output")
    chunks: list[str] = []
    if not root.exists():
        return ""
    for p in root.rglob("*"):
        if p.suffix.lower() in {".json", ".md", ".txt"} and p.stat().st_size < 2500000:
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")[:220000]
                if host in text or "target" in text.lower() or str(p).startswith("reports/output/tool"):
                    chunks.append(text)
            except Exception:
                pass
    return "\n".join(chunks)


def surface_snapshot(target: str) -> dict[str, Any]:
    host = host_from_target(target)
    base = ".".join(host.split(".")[-2:]) if "." in host else host
    text = scan_report_text(target)
    urls = sorted(set(u for u in re.findall(r"https?://[^\s\"'<>),]+", text) if host in u or base in u))
    domains = sorted(set(re.findall(r"\b[a-zA-Z0-9._-]+\." + re.escape(base) + r"\b", text)))
    paths = sorted(set(re.findall(r"(?<![A-Za-z0-9])/[A-Za-z0-9_./?=&%:-]{2,}", text)))
    params = sorted(set(re.findall(r"[?&]([A-Za-z0-9_:-]{2,})=", text)))
    return {"hosts": domains[:10], "urls": urls[:8], "paths": paths[:12], "params": params[:14]}


def build_steps(target: str, include_google_pair: bool, max_cycles: int) -> list[Step]:
    tq = shlex.quote(target)
    hq = shlex.quote(host_from_target(target))
    sq = shlex.quote(str(SESSION_SCOPE))
    aq = shlex.quote(str(ARTEMIS_LIVE_CONFIG))
    steps = [
        Step("STAGE 1", "Mission Preflight", f"python3 mission_preflight_cli.py --target {tq} --scope-policy {sq}", "Now I will validate target scope, DNS, typo risk, stale output state, and mission readiness.", 600, False),
        Step("STAGE 2", "Tool Doctor", "python3 tool_doctor_cli.py --install --yes --top 100", "Now I will repair the top safe helper toolset and make the arsenal stronger before evidence collection.", 1800, True),
        Step("STAGE 2", "Tool PATH Repair", "python3 tool_path_repair_cli.py", "Now I will check whether binaries are visible in PATH and repair user-local links.", 600, True),
        Step("STAGE 2", "Coverage Matrix", "python3 coverage_matrix.py", "Now I will check every coverage area so weak zones are visible before the scan.", 600, True),
        Step("STAGE 2", "Mega Tools Status", "python3 mega_tools_cli.py --status", "Now I will inspect the larger tool registry and record available modules.", 900, True),
        Step("STAGE 3", "Neural Tool Mind", f"python3 tool_mind_cli.py --target {tq} --mode crazy --install-needed --yes", "Now I will think about the target and decide which helper tools matter most.", 3600, True),
        Step("STAGE 3", "Passive Domain Recon", f"python3 domain_recon_cli.py --target {hq}", "Now I will find subdomains, archived URLs, public routes, and interesting exposed paths inside scope.", 1800, True),
        Step("STAGE 3", "AEGIS Public Search", f"python3 aegis_public_search_cli.py --target {tq}", "Now I will collect public intelligence sources and look for admin/API/staging hints.", 900, True),
        Step("STAGE 3", "AEGIS Feedback Planner", f"python3 aegis_feedback_cli.py --target {tq}", "Now I will convert observations into prioritized safe review actions.", 900, True),
        Step("STAGE 3", "ARTEMIS Passive Intelligence", f"python3 artemis_autonomous_cli.py --config {aq} --scope-policy {sq} --once", "Now I will generate passive risk predictions using public evidence and historical patterns.", 2400, True),
        Step("STAGE 4", "Safe Evidence Loop", f"python3 safe_loop_v2_cli.py --target {tq} --mode comprehensive --scope-policy {sq} --max-cycles {max_cycles} --yes", "Now I will safely review URLs, headers, parameters, and auth-sensitive routes with evidence-first checks.", 3600, True),
        Step("STAGE 4", "Comprehensive Category Review", f"python3 comprehensive_suite_cli.py --target {tq} --scope-policy {sq} --yes", "Now I will run broad non-destructive category review and create precise manual-review items.", 2400, True),
        Step("STAGE 4", "Proxy Passive Bridge", f"python3 artemis_proxy_passive_cli.py --target {tq} --limit 100", "Now I will import passive proxy observations if a local proxy API is available.", 900, True),
    ]
    if include_google_pair:
        steps.append(Step("STAGE 4", "Two Account Precision", f"python3 google_pair_cli.py --target {tq} --profile default --max-pages 25 --skip-login --skip-if-missing --yes", "Now I will compare saved account states if available to reduce access-control false positives.", 3600, True))
    steps += [
        Step("STAGE 5", "Advanced Modes Correlation", f"python3 vulnscope_modes_cli.py --target {tq} --scope-policy {sq}", "Now I will correlate advanced mode output and reduce duplicate or weak signals.", 2400, True),
        Step("STAGE 5", "Normalize Evidence", f"python3 normalize_cli.py --target {tq}", "Now I will normalize hosts, URLs, endpoints, parameters, and evidence into one corpus.", 900, True),
        Step("STAGE 5", "Asset Graph", f"python3 asset_graph_cli.py --target {tq}", "Now I will build the target graph and connect hosts, routes, parameters, and findings.", 900, True),
        Step("STAGE 5", "API Intelligence", f"python3 api_intel_cli.py --target {tq}", "Now I will map API-like endpoints, object routes, and authentication review surfaces.", 900, True),
        Step("STAGE 5", "Auth Differential v2", "python3 auth_diff_v2_cli.py", "Now I will use stored authentication evidence if available and mark unavailable areas as not tested.", 900, True),
        Step("STAGE 5", "Target History", f"python3 target_history_cli.py --target {tq}", "Now I will compare this run with previous target history and changes.", 900, True),
        Step("STAGE 6", "Evidence Cards", f"python3 evidence_cards_cli.py --target {tq}", "Now I will convert raw evidence into readable finding cards.", 900, True),
        Step("STAGE 6", "Reportability Ranking", f"python3 reportability_cli.py --target {tq}", "Now I will rank findings by severity, confidence, and manual validation value.", 900, True),
        Step("STAGE 6", "Mission Verdict Report", f"python3 mission_verdicts_cli.py --target {tq}", "Now I will consolidate every module into a final verdict table.", 900, True),
        Step("STAGE 6", "Canary Review Matrix", f"python3 canary_review_matrix_cli.py --target {tq}", "Now I will generate the 20-area canary review matrix for the current target only.", 900, True),
        Step("STAGE 6", "Final Report", f"python3 report_v2_cli.py --target {tq}", "Now I will build the executive report.", 900, True),
        Step("STAGE 6", "JARVIS Summary", f"python3 jarvis_summary_cli.py --target {tq}", "Now I will print the terminal summary and next actions.", 900, True),
    ]
    return steps


def plan_only(target: str, include_subdomains: bool, include_google_pair: bool, max_cycles: int) -> int:
    target = normalize_target(target)
    write_scope(target, include_subdomains)
    write_artemis_config(target)
    steps = build_steps(target, include_google_pair, max_cycles)
    print(json.dumps({"target": target, "steps": [s.__dict__ for s in steps]}, indent=2))
    return 0


def load_json(path: str) -> Any:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


def print_verdicts(ui: AgentTerminalUI) -> dict[str, Any]:
    data = load_json("reports/output/mission-verdicts/mission-verdicts.json")
    rows = data.get("rows", []) if isinstance(data, dict) else []
    summary = data.get("summary", {}) if isinstance(data, dict) else {}
    print("\n" + ui.border("Module Verdicts"))
    print(ui.c(f"{'Module':<24} {'Verdict':<18} {'Severity':<10} Item Tested", WHITE + BOLD))
    print(ui.c("─" * ui.width, CYAN))
    for row in rows[:26]:
        module = str(row.get("module", "unknown"))[:23]
        verdict = str(row.get("verdict", "REVIEW"))[:17]
        severity = str(row.get("severity", "INFO"))[:9]
        item = str(row.get("item", "n/a"))[:60]
        col = GREEN
        if "HIGH" in verdict.upper() or severity.upper() in {"CRITICAL", "HIGH"}:
            col = YELLOW if severity.upper() != "CRITICAL" else RED
        elif any(x in verdict.upper() for x in ["ERROR", "FAILED", "MISSING"]):
            col = RED
        print(f"{ui.c(f'{module:<24}', CYAN)} {ui.c(f'{verdict:<18}', col + BOLD)} {ui.c(f'{severity:<10}', col)} {item}")
    if not rows:
        print(ui.c("No verdict rows generated yet. Check reports/logs for module failures.", YELLOW))
    return {"rows": rows, "summary": summary}


def write_final(ui: AgentTerminalUI, results: list[dict[str, Any]], target: str) -> dict[str, Any]:
    verdicts = print_verdicts(ui)
    rows = verdicts.get("rows", [])
    summary = verdicts.get("summary", {})
    severity = summary.get("severity", {}) if isinstance(summary, dict) else {}
    high = [r for r in rows if str(r.get("severity", "")).upper() in {"CRITICAL", "HIGH"} or str(r.get("verdict", "")).upper() in {"REVIEW_HIGH", "HIGH_PRIORITY", "VULNERABLE"}]
    payload = {
        "target": target,
        "host": host_from_target(target),
        "tasks": len(results),
        "ok": len([r for r in results if r.get("ok")]),
        "failed": len([r for r in results if not r.get("ok")]),
        "severity": severity,
        "high_priority_rows": high[:30],
        "results": results,
        "reports": REPORTS,
        "ui": {"total_i": ui.total_i, "total_o": ui.total_o, "total_r": ui.total_r},
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "live-run.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# VulnScope Live Autonomous Run — {target}", "", f"Host: `{host_from_target(target)}`", f"Tasks: `{payload['tasks']}`", f"OK: `{payload['ok']}`", f"Failed/review: `{payload['failed']}`", f"UI I/O/R: `{ui.total_i}/{ui.total_o}/{ui.total_r}`", "", "## High Priority Rows"]
    if high:
        for row in high[:30]:
            lines.append(f"- `{row.get('module')}` `{row.get('item')}` verdict=`{row.get('verdict')}` severity=`{row.get('severity')}` evidence=`{str(row.get('evidence',''))[:300]}`")
    else:
        lines.append("- No high-priority row generated. Review manual candidates in mission-verdicts.md.")
    lines += ["", "## Reports"]
    for name, path in REPORTS.items():
        lines.append(f"- {name}: `{path}`")
    (OUT / "live-run.md").write_text("\n".join(lines), encoding="utf-8")
    return payload


def run_live(target: str, include_subdomains: bool, include_google_pair: bool, workers: int, max_cycles: int) -> int:
    target = normalize_target(target)
    clean_info = reset_target_outputs(target)
    OUT.mkdir(parents=True, exist_ok=True)
    write_scope(target, include_subdomains)
    write_artemis_config(target)
    os.environ["PYTHONUNBUFFERED"] = "1"
    steps = build_steps(target, include_google_pair, max_cycles)
    ui = AgentTerminalUI(total_steps=len(steps))
    ui.banner(target, include_subdomains, include_google_pair, workers, max_cycles)
    ui.agent("Authorization is confirmed. I reset old target outputs, locked scope to the entered URL, and will only map evidence for this current target.", clean_info)
    results: list[dict[str, Any]] = []
    current_stage = ""
    start = time.time()
    for step in steps:
        if step.stage != current_stage:
            current_stage = step.stage
            ui.agent(step.thought)
        else:
            ui.agent(step.thought)
        result = run_step(step, ui)
        results.append(result)
        snap = surface_snapshot(target)
        ui.agent(f"After {step.label}, I am updating the map for {host_from_target(target)} only.", snap)
        if not result.get("ok") and not result.get("optional"):
            ui.agent(f"{step.label} failed and is required. I will stop so the final result is not misleading.", {"exit_code": result.get("exit_code"), "error": result.get("error")})
            break
    payload = write_final(ui, results, target)
    print("\n" + ui.border("Final Output"))
    print(ui.c(f"TARGET                : {target}", WHITE + BOLD))
    print(ui.c(f"HOST                  : {host_from_target(target)}", WHITE + BOLD))
    print(ui.c(f"TOTAL MODULE TASKS    : {payload['tasks']}", WHITE))
    print(ui.c(f"SUCCESSFUL TASKS      : {payload['ok']}", GREEN + BOLD))
    print(ui.c(f"FAILED / REVIEW TASKS : {payload['failed']}", YELLOW if payload["failed"] else GREEN))
    print(ui.c(f"TOTAL TIME            : {round(time.time() - start, 2)}s", WHITE))
    print(ui.c("SEVERITY SUMMARY      : " + json.dumps(payload.get("severity", {}), ensure_ascii=False), WHITE))
    if payload["high_priority_rows"]:
        print(ui.c("\nTOP HIGH-PRIORITY ROWS", RED + BOLD))
        for row in payload["high_priority_rows"][:10]:
            print(ui.c("  ├─ ", RED) + f"[{row.get('severity')}] {row.get('module')} :: {row.get('item')} :: {row.get('verdict')}")
    else:
        print(ui.c("\nNo high-priority row generated. Review manual candidates in mission-verdicts.md.", YELLOW))
    print(ui.c("\nREPORTS SAVED", CYAN + BOLD))
    for path in REPORTS.values():
        print(ui.c("  ├─ ", CYAN) + path)
    print(ui.c("\nNEXT ACTION", MAGENTA + BOLD))
    print("  Open reports/output/mission-verdicts/mission-verdicts.md first, then validate HIGH/REVIEW rows manually under authorization.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScope target-isolated autonomous live CLI")
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
