#!/usr/bin/env python3
from __future__ import annotations

import argparse

from workflow.assessment_state import AssessmentState
from workflow.checkpoint_store import load_checkpoint, save_checkpoint
from workflow.phase_runner import PhaseRunner

VERSION = "1.0.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VulnScope one-command authorized assessment workflow")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target", help="Authorized target domain or URL")
    parser.add_argument("--mode", default="bounty", choices=["bounty", "pentest", "comprehensive", "learning"])
    parser.add_argument("--resume", action="store_true", help="Resume checkpoint for the same target if present")
    parser.add_argument("--yes", action="store_true", help="Confirm scope statement non-interactively")
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
    print("│ Phase-based workflow: recon → profile → agents → validation → report       │")
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
    print("\n[+] Workflow completed")
    print("[+] Final report: reports/output/workflow/vulnscope-assessment-report.md")
    print("[+] Checkpoint: reports/output/workflow/<target>-checkpoint.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
