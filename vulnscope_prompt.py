#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

try:
    import readline  # noqa: F401
except Exception:  # pragma: no cover
    pass

from core.ai_brain import AIBrain
from core.context_store import ContextStore
from core.prompt_engine import PromptEngine
from core.tool_manager import ToolManager


BANNER = """
🔥 VulnScope Prompt Engine – Cognitive Tool Orchestrator
Type natural-language assessment requests.
Examples:
  full recon on testphp.vulnweb.com in lab mode
  check example.com in bugbounty mode
Commands:
  tools       list registered tools
  last        show last result summary
  exit        quit
"""


def print_tools(manager: ToolManager) -> None:
    rows = manager.list_tools()
    if not rows:
        print("No registered tools found. Run: python3 scripts/diagnose_tools.py")
        return
    for row in rows:
        print(f"{row.get('phase', '-')}: {row.get('name', row.get('tool_id'))} enabled={row.get('enabled')} approved={row.get('approved_run')}")


def main() -> int:
    manager = ToolManager()
    manager.reconcile_installed_tools(approve_known=True, enable=True)
    brain = AIBrain()
    context = ContextStore()
    engine = PromptEngine(manager, brain, context)
    last_result = None
    print(BANNER)
    while True:
        try:
            user_input = input("💬 > ").strip()
        except KeyboardInterrupt:
            print("\nExiting.")
            break
        except EOFError:
            print("\nExiting.")
            break
        if not user_input:
            continue
        if user_input.lower() in {"exit", "quit"}:
            break
        if user_input.lower() == "tools":
            print_tools(manager)
            continue
        if user_input.lower() == "last":
            print(json.dumps(last_result or {"message": "No previous result"}, indent=2, ensure_ascii=False))
            continue
        if last_result and any(word in user_input.lower() for word in ["critical", "high", "show", "summary"]):
            follow = engine.answer_followup(user_input)
            print(json.dumps(follow, indent=2, ensure_ascii=False))
            continue
        plan = engine.parse_prompt(user_input)
        print("📋 Plan:")
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        result = engine.execute_plan(plan)
        last_result = result
        if "error" in result:
            print("❌ " + str(result["error"]))
            continue
        response = brain.generate_response(user_input, plan, result)
        print("\n🤖 " + response + "\n")
        Path("last_scan_results.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print("Results saved to last_scan_results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
