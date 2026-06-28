#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import selectors
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
REPORT_DIR = ROOT / "reports" / "output" / "agent"
PROFILE_ROOT = Path.home() / ".vulnscope" / "google_profiles"
SCOPE_POLICY = ROOT / "scope_policy.yaml"
AUTONOMY_POLICY = ROOT / "autonomy_policy.yaml"

SAFE_DEFAULT_PROVIDER_ORDER = [
    "mistral",
    "local-rules",
    "ollama",
    "openrouter",
    "gemini",
    "fireworks",
    "cohere",
    "groq",
    "deepseek",
    "openai",
    "anthropic",
]

STEP_DESCRIPTIONS = {
    "authenticated_chrome_profiles": "Using saved Chrome account_a/account_b sessions for authenticated page mapping and account-difference review.",
    "passive_domain_recon": "Collecting passive domain intelligence, archived URLs, and high-value URL candidates.",
    "safe_auto_arsenal": "Running safe bug-bounty tool profile. This may take time if tools crawl many pages or wait on DNS/network.",
    "ai_autopilot": "Letting the AI agent review collected evidence, plan next review steps, and produce candidate findings.",
    "finding_quality": "Scoring findings and filtering noisy candidates.",
    "evidence_graph": "Building evidence graph from recon, auth review, tool output, and quality data.",
    "report_v2": "Generating final executive report.",
    "dashboard_once": "Rendering final dashboard status.",
}


@dataclass
class StepResult:
    name: str
    command: list[str]
    started_at: float
    ended_at: float
    returncode: int
    stdout_tail: str
    stderr_tail: str
    skipped: bool = False
    reason: str = ""


class VulnScopeAgent:
    def __init__(self, target: str, provider: str, mode: str, max_auth_pages: int, yes: bool, no_auth: bool, skip_tools: bool, allow_scope_write: bool, provider_fallback: bool = True, live: bool = True, heartbeat_seconds: int = 8) -> None:
        self.target = target.rstrip("/")
        self.provider = provider
        self.mode = mode
        self.max_auth_pages = max_auth_pages
        self.yes = yes
        self.no_auth = no_auth
        self.skip_tools = skip_tools
        self.allow_scope_write = allow_scope_write
        self.provider_fallback = provider_fallback
        self.live = live
        self.heartbeat_seconds = heartbeat_seconds
        self.provider_test_results: dict[str, dict] = {}
        self.results: list[StepResult] = []
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

    def run(self) -> int:
        self._banner()
        self._validate_target()
        self._prepare_policies()
        self._detect_provider()
        self._run_authenticated_profile_review()
        self._run_passive_recon()
        self._run_safe_tooling()
        self._run_autopilot()
        self._run_evidence_and_reports()
        self._write_summary()
        self._print_final()
        return 0

    def _banner(self) -> None:
        print("\n┌──────────────────────────────────────────────────────────────┐")
        print("│ VulnScope Autonomous Agent - Live Mode                       │")
        print("│ Target → auth context → recon → safe tooling → AI → report   │")
        print("│ Safe default: no password extraction, no DB dump, no exploit │")
        print("└──────────────────────────────────────────────────────────────┘")
        print(f"Target : {self.target}")
        print(f"Mode   : {self.mode}")
        print(f"AI     : {self.provider}")
        print(f"Live   : {self.live}\n")

    def _validate_target(self) -> None:
        parsed = urlparse(self.target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise SystemExit("[!] Target must be a full URL, e.g. https://example.com")

    def _target_host(self) -> str:
        return urlparse(self.target).netloc.split(":")[0]

    def _prepare_policies(self) -> None:
        host = self._target_host()
        if not SCOPE_POLICY.exists() or self.allow_scope_write:
            self._write_scope_policy(host)
        if not AUTONOMY_POLICY.exists():
            self._write_autonomy_policy()
        print(f"[+] Scope policy ready: {SCOPE_POLICY}")
        print(f"[+] Autonomy policy ready: {AUTONOMY_POLICY}")

    def _write_scope_policy(self, host: str) -> None:
        scheme = urlparse(self.target).scheme or "https"
        SCOPE_POLICY.write_text(f"""name: vulnscope-autonomous-target
allowed_hosts:
  - {host}
allowed_schemes:
  - {scheme}
max_requests_per_minute: 30
active_testing_allowed: false
authenticated_testing_allowed: true
notes: "Auto-generated for the user-provided authorized target. Safe autonomous review only."
""", encoding="utf-8")

    def _write_autonomy_policy(self) -> None:
        AUTONOMY_POLICY.write_text("""level: 2
max_cycles: 3
max_runtime_minutes: 45
allow_active_tools: false
allow_authenticated_review: true
allow_model_council: true
allow_har_import: true
allow_report_generation: true
require_scope_policy: true
stop_on_scope_block: true
min_quality_threshold: 0.45
notes: "Safe autonomous orchestration. No destructive actions. No credential capture."
""", encoding="utf-8")

    def _detect_provider(self) -> None:
        if self.provider and self.provider != "auto" and not self.provider_fallback:
            print(f"[+] Provider fallback disabled. Using: {self.provider}")
            return
        candidates = SAFE_DEFAULT_PROVIDER_ORDER if self.provider == "auto" else [self.provider] + [p for p in SAFE_DEFAULT_PROVIDER_ORDER if p != self.provider]
        print("\n┌─ AI provider check ──────────────────────────────────────────┐")
        print("│ Testing configured APIs. The first live working provider wins │")
        print("└───────────────────────────────────────────────────────────────┘")
        for provider in candidates:
            ok, info = self._provider_usable(provider)
            self.provider_test_results[provider] = info
            print(f"    {'✓' if ok else '✗'} {provider} ({info.get('elapsed_seconds', 0)}s)")
            if ok:
                self.provider = provider
                print(f"[+] Selected working provider: {self.provider}\n")
                return
        self.provider = "local-rules"
        print("[!] No cloud provider passed. Falling back to local-rules.\n")

    def _provider_usable(self, provider: str) -> tuple[bool, dict]:
        if provider == "local-rules":
            return True, {"provider": provider, "status": "local_fallback", "elapsed_seconds": 0}
        started = time.time()
        try:
            proc = subprocess.run([sys.executable, "ai_provider_cli.py", "--test", "--provider", provider], cwd=ROOT, text=True, capture_output=True, timeout=90)
            combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
            info = {"provider": provider, "returncode": proc.returncode, "elapsed_seconds": round(time.time() - started, 2), "output_tail": combined[-1800:]}
            return proc.returncode == 0 and "[+]" in combined, info
        except Exception as exc:
            return False, {"provider": provider, "error": str(exc), "elapsed_seconds": round(time.time() - started, 2)}

    def _run_authenticated_profile_review(self) -> None:
        if self.no_auth:
            self._skip("authenticated_chrome_profiles", "Disabled with --no-auth")
            return
        account_a = PROFILE_ROOT / "account_a"
        account_b = PROFILE_ROOT / "account_b"
        if not account_a.exists() or not account_b.exists():
            self._skip("authenticated_chrome_profiles", f"Missing {account_a} or {account_b}")
            return
        self._run_step("authenticated_chrome_profiles", [sys.executable, "chrome_auth_cli.py", "--target", self.target, "--account", "both", "--max-pages", str(self.max_auth_pages), "--compare"], timeout=600)

    def _run_passive_recon(self) -> None:
        self._run_step("passive_domain_recon", [sys.executable, "domain_recon_cli.py", "--target", self.target], timeout=300)

    def _run_safe_tooling(self) -> None:
        if self.skip_tools:
            self._skip("safe_auto_arsenal", "Disabled with --skip-tools")
            return
        self._run_step("safe_auto_arsenal", [sys.executable, "auto_mode.py", "--url", self.target, "--profile", "bug-bounty-safe", "--full"], timeout=900)

    def _run_autopilot(self) -> None:
        self._run_step("ai_autopilot", [sys.executable, "autopilot_cli.py", "--target", self.target, "--mode", self.mode, "--provider", self.provider, "--yes"], timeout=1200)

    def _run_evidence_and_reports(self) -> None:
        self._run_step("finding_quality", [sys.executable, "finding_quality_cli.py"], timeout=180)
        self._run_step("evidence_graph", [sys.executable, "evidence_graph_cli.py"], timeout=180)
        self._run_step("report_v2", [sys.executable, "report_v2_cli.py", "--target", self.target], timeout=300)
        self._run_step("dashboard_once", [sys.executable, "dashboard_cli.py", "--once"], timeout=120)

    def _run_step(self, name: str, command: list[str], timeout: int) -> None:
        print("\n╭" + "─" * 70 + "╮")
        print(f"│ STEP: {name[:62]:62} │")
        print("╰" + "─" * 70 + "╯")
        print(f"[i] {STEP_DESCRIPTIONS.get(name, 'Running module.')} ")
        print("[cmd] " + " ".join(command))
        started = time.time()
        if self.live:
            result = self._run_step_live(name, command, timeout, started)
        else:
            result = self._run_step_capture(name, command, timeout, started)
        self.results.append(result)
        if result.returncode == 0:
            print(f"[✓] {name} completed in {round(result.ended_at - result.started_at, 2)}s")
        else:
            print(f"[!] {name} returned {result.returncode}; continuing safely")

    def _run_step_live(self, name: str, command: list[str], timeout: int, started: float) -> StepResult:
        output_lines: list[str] = []
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spin_i = 0
        last_heartbeat = time.time()
        proc = subprocess.Popen(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
        sel = selectors.DefaultSelector()
        if proc.stdout:
            sel.register(proc.stdout, selectors.EVENT_READ)
        try:
            while True:
                if time.time() - started > timeout:
                    proc.kill()
                    ended = time.time()
                    return StepResult(name, command, started, ended, 124, "\n".join(output_lines)[-4000:], "timeout", reason="timeout")
                events = sel.select(timeout=0.5)
                for key, _ in events:
                    line = key.fileobj.readline()
                    if line:
                        clean = line.rstrip()
                        output_lines.append(clean)
                        print(f"[{name}] {clean}")
                if proc.poll() is not None:
                    # drain remaining output
                    if proc.stdout:
                        for line in proc.stdout.readlines():
                            clean = line.rstrip()
                            if clean:
                                output_lines.append(clean)
                                print(f"[{name}] {clean}")
                    ended = time.time()
                    return StepResult(name, command, started, ended, proc.returncode or 0, "\n".join(output_lines)[-4000:], "")
                if time.time() - last_heartbeat >= self.heartbeat_seconds:
                    elapsed = int(time.time() - started)
                    print(f"[{name}] {spinner[spin_i % len(spinner)]} still running... {elapsed}s elapsed. Waiting for tool output.")
                    spin_i += 1
                    last_heartbeat = time.time()
        finally:
            try:
                sel.close()
            except Exception:
                pass

    def _run_step_capture(self, name: str, command: list[str], timeout: int, started: float) -> StepResult:
        try:
            proc = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
            ended = time.time()
            return StepResult(name, command, started, ended, proc.returncode, (proc.stdout or "")[-4000:], (proc.stderr or "")[-4000:])
        except subprocess.TimeoutExpired as exc:
            ended = time.time()
            return StepResult(name, command, started, ended, 124, str(exc.stdout or "")[-4000:], str(exc.stderr or "")[-4000:], reason="timeout")
        except Exception as exc:
            ended = time.time()
            return StepResult(name, command, started, ended, 1, "", str(exc), reason="exception")

    def _skip(self, name: str, reason: str) -> None:
        now = time.time()
        self.results.append(StepResult(name, [], now, now, 0, "", "", skipped=True, reason=reason))
        print(f"[-] Skipped {name}: {reason}")

    def _write_summary(self) -> None:
        summary = {
            "target": self.target,
            "provider": self.provider,
            "provider_tests": self.provider_test_results,
            "mode": self.mode,
            "safe_auth_profiles_used": not self.no_auth,
            "steps": [asdict(r) for r in self.results],
            "artifacts": {
                "auth_comparison": "reports/output/auth/chrome-profile-account-comparison.md",
                "agent_plan": "reports/output/autonomy/autonomy-plan.md",
                "evidence_graph": "reports/output/evidence-graph/evidence-graph.md",
                "report_v2": "reports/output/report-v2/executive-report-v2.md",
                "dashboard": "python3 dashboard_cli.py --once",
            },
            "safety": {"credentials_collected": False, "passwords_extracted": False, "destructive_actions": False, "active_testing_allowed_by_default": False},
        }
        (REPORT_DIR / "vulnscope-agent-run.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        md = ["# VulnScope Autonomous Agent Run", "", f"Target: `{self.target}`", f"Provider: `{self.provider}`", f"Mode: `{self.mode}`", "", "## Steps"]
        for r in self.results:
            status = "skipped" if r.skipped else ("ok" if r.returncode == 0 else f"returned {r.returncode}")
            md.append(f"- **{r.name}**: {status} {('- ' + r.reason) if r.reason else ''}")
        md.extend(["", "## Main artifacts", "- `reports/output/auth/chrome-profile-account-comparison.md`", "- `reports/output/autonomy/autonomy-plan.md`", "- `reports/output/evidence-graph/evidence-graph.md`", "- `reports/output/report-v2/executive-report-v2.md`", "", "## Safety", "- No Google password collection or extraction.", "- Existing local Chrome profiles are reused only as authenticated browser contexts.", "- Safe autonomous review only; findings remain review candidates until validated."])
        (REPORT_DIR / "vulnscope-agent-run.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    def _print_final(self) -> None:
        print("\n┌──────────────────── Final Output ────────────────────┐")
        print("│ Agent run finished. Review these files:               │")
        print("│ reports/output/agent/vulnscope-agent-run.md           │")
        print("│ reports/output/report-v2/executive-report-v2.md       │")
        print("│ reports/output/evidence-graph/evidence-graph.md       │")
        print("└───────────────────────────────────────────────────────┘")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="One-command safe autonomous VulnScope agent")
    parser.add_argument("--target", required=True, help="Authorized target URL, e.g. https://example.com")
    parser.add_argument("--provider", default="auto", help="AI provider: auto, mistral, local-rules, ollama, openrouter, etc.")
    parser.add_argument("--mode", default="comprehensive", choices=["bounty", "comprehensive"])
    parser.add_argument("--max-auth-pages", type=int, default=12)
    parser.add_argument("--no-auth", action="store_true", help="Do not use saved Chrome account_a/account_b profiles")
    parser.add_argument("--skip-tools", action="store_true", help="Skip Auto Arsenal external tooling")
    parser.add_argument("--no-provider-fallback", action="store_true", help="Use the requested provider without testing/fallback")
    parser.add_argument("--no-live", action="store_true", help="Disable live module output streaming")
    parser.add_argument("--heartbeat", type=int, default=8, help="Seconds between live still-running updates")
    parser.add_argument("--yes", action="store_true", help="Acknowledge authorized target and allow autonomous run")
    parser.add_argument("--no-scope-write", action="store_true", help="Do not auto-create/update scope_policy.yaml")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.yes:
        print("[!] Add --yes to confirm this is your owned or explicitly authorized target.")
        return 2
    agent = VulnScopeAgent(
        target=args.target,
        provider=args.provider,
        mode=args.mode,
        max_auth_pages=args.max_auth_pages,
        yes=args.yes,
        no_auth=args.no_auth,
        skip_tools=args.skip_tools,
        allow_scope_write=not args.no_scope_write,
        provider_fallback=not args.no_provider_fallback,
        live=not args.no_live,
        heartbeat_seconds=args.heartbeat,
    )
    return agent.run()


if __name__ == "__main__":
    raise SystemExit(main())
