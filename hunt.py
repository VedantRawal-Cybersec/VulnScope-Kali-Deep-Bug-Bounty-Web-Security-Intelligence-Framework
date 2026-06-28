#!/usr/bin/env python3
from __future__ import annotations

import argparse

from agent_core.controller import AgentCoreController
from workflow.assessment_state import AssessmentState
from workflow.checkpoint_store import load_checkpoint, save_checkpoint
from workflow.phase_runner import PhaseRunner

VERSION = "1.2.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope one-command authorized assessment workflow")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", help="Authorized target domain or URL")
    parser.add_argument("--mode", default="bounty", choices=["bounty", "pentest", "comprehensive", "learning"])
    parser.add_argument("--resume", action="store_true", help="Resume checkpoint for the same target if present")
    parser.add_argument("--yes", action="store_true", help="Confirm scope statement non-interactively")
    parser.add_argument("--agent-core", action="store_true", help="Run CAI-inspired agent core after phase workflow")
    parser.add_argument("--provider", help="AI provider: anthropic/claude/deepseek/openai/groq/openrouter/ollama")
    parser.add_argument("--dry-run", action="store_true", help="Plan actions without running optional external tool stages")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print(f"VulnScope Assessment Workflow {VERSION}")
        return 0
    if not args.target:
        print("[!] Provide --target")
        return 1

    print("┌──────────────────────── VulnScope Assessment Workflow ─────────────────────┐")
    print("│ Phase workflow + specialist agents + optional AI provider review.           │")
    print("│ Run only on owned or explicitly authorized assets.                         │")
    print("└────────────────────────────────────────────────────────────────────────────┘")
    if not args.yes:
        answer = input("Confirm this target is authorized and in scope? yes/no: ").strip().lower()
        if answer not in {"yes", "y"}:
            print("[!] Cancelled")
            return 1

    state = load_checkpoint(args.target) if args.resume else None
    if state:
        print(f"[+] Resuming checkpoint at phase: {state.current_phase}")
    else:
        state = AssessmentState(target=args.target, mode=args.mode)
        save_checkpoint(state)

    PhaseRunner(state).run_all()

    if args.agent_core:
        print("\n[+] Running CAI-inspired agent core")
        AgentCoreController(target=args.target, mode=args.mode, auto_yes=args.yes, dry_run=args.dry_run, provider=args.provider).run()
        print("[+] Agent core summary: reports/output/agent_core/agent-core-summary.json")
        print("[+] AI review: reports/output/agent_core/ai-review.md")

    print("\n[+] Workflow completed")
    print("[+] Final report: reports/output/workflow/vulnscope-assessment-report.md")
    print("[+] Checkpoint: reports/output/workflow/<target>-checkpoint.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
