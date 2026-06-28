#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent_core.controller import AgentCoreController
from findings.quality import load_findings_from_reports, reduce_low_quality
from importers.har_importer import save_import
from reports.report_v2 import build_report_v2
from scope.policy import load_scope_policy, write_default_scope_policy
from workflow.assessment_state import AssessmentState
from workflow.checkpoint_store import load_checkpoint, save_checkpoint
from workflow.phase_runner import PhaseRunner

VERSION = "1.4.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope one-command authorized assessment workflow")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", help="Authorized target domain or URL")
    parser.add_argument("--mode", default="bounty", choices=["bounty", "pentest", "comprehensive", "learning"])
    parser.add_argument("--resume", action="store_true", help="Resume checkpoint for the same target if present")
    parser.add_argument("--yes", action="store_true", help="Confirm scope statement non-interactively")
    parser.add_argument("--agent-core", action="store_true", help="Run CAI-inspired agent core after phase workflow")
    parser.add_argument("--provider", help="AI provider: anthropic/claude/deepseek/openai/groq/openrouter/ollama/mistral/fireworks/cohere")
    parser.add_argument("--model-council", action="store_true", help="Run multi-model council review across configured providers")
    parser.add_argument("--scope-policy", default="scope_policy.yaml", help="Scope policy YAML/JSON path")
    parser.add_argument("--init-scope-policy", action="store_true", help="Create default scope_policy.yaml and exit")
    parser.add_argument("--har-import", help="Import browser/Burp HAR before agent-core review")
    parser.add_argument("--quality", action="store_true", help="Run finding quality and dedupe engine at the end")
    parser.add_argument("--report-v2", action="store_true", help="Generate executive report v2 at the end")
    parser.add_argument("--dry-run", action="store_true", help="Plan actions without running optional external tool stages")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print(f"VulnScope Assessment Workflow {VERSION}")
        return 0
    if args.init_scope_policy:
        path = write_default_scope_policy(args.scope_policy)
        print(f"[+] Scope policy ready: {path}")
        return 0
    if not args.target:
        print("[!] Provide --target")
        return 1

    print("┌──────────────────────── VulnScope Assessment Workflow ─────────────────────┐")
    print("│ Phase workflow + specialist agents + optional model-council AI review.      │")
    print("│ Scope policy, HAR import, quality engine, benchmark/report v2 ready.        │")
    print("└────────────────────────────────────────────────────────────────────────────┘")

    policy = load_scope_policy(args.scope_policy)
    decision = policy.check(args.target)
    if not decision.allowed:
        print(f"[!] Scope policy blocked target: {decision.reason}")
        print(f"[!] Edit {args.scope_policy} or run: python3 hunt.py --init-scope-policy")
        return 1
    print(f"[+] Scope policy allowed target: {decision.reason}")

    if not args.yes:
        answer = input("Confirm this target is authorized and in scope? yes/no: ").strip().lower()
        if answer not in {"yes", "y"}:
            print("[!] Cancelled")
            return 1

    if args.har_import:
        out = save_import(args.har_import)
        print(f"[+] HAR imported: {out}")

    state = load_checkpoint(args.target) if args.resume else None
    if state:
        print(f"[+] Resuming checkpoint at phase: {state.current_phase}")
    else:
        state = AssessmentState(target=args.target, mode=args.mode)
        save_checkpoint(state)

    PhaseRunner(state).run_all()

    if args.agent_core:
        print("\n[+] Running CAI-inspired agent core")
        AgentCoreController(target=args.target, mode=args.mode, auto_yes=args.yes, dry_run=args.dry_run, provider=args.provider, council=args.model_council).run()
        print("[+] Agent core summary: reports/output/agent_core/agent-core-summary.json")
        print("[+] AI review: reports/output/agent_core/ai-review.md")
        if args.model_council:
            print("[+] Council consensus: reports/output/agent_core/model-council/council-consensus.md")

    if args.quality:
        items = load_findings_from_reports([
            "reports/output/agent_core/agent-core-summary.json",
            "reports/output/workflow/reportability-scores.json",
            "reports/output/imports/har-import.json",
        ])
        quality = reduce_low_quality(items)
        out = Path("reports/output/finding-quality.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(quality, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] Finding quality output: {out}")

    if args.report_v2:
        outputs = build_report_v2(args.target)
        print(f"[+] Report v2 markdown: {outputs['markdown']}")
        print(f"[+] Report v2 JSON: {outputs['json']}")

    print("\n[+] Workflow completed")
    print("[+] Final report: reports/output/workflow/vulnscope-assessment-report.md")
    print("[+] Checkpoint: reports/output/workflow/<target>-checkpoint.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
