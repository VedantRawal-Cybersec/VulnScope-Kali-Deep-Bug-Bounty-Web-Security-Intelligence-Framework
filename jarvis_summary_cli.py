#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

REPORTS = {
    "tool_mind": "reports/output/tool-mind/tool-mind.json",
    "tool_path_repair": "reports/output/tool-path-repair/tool-path-repair.json",
    "normalized": "reports/output/normalized/normalized-evidence.json",
    "api_intel": "reports/output/api-intel/api-intel.json",
    "evidence_cards": "reports/output/evidence-cards/evidence-cards.json",
    "reportability": "reports/output/reportability/reportability.json",
    "google_pair": "reports/output/google-pair/google-pair-run.json",
}


def load(path: str) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def pick_cards(data: Any, limit: int = 10) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    cards = data.get("cards") or data.get("candidates") or []
    if not isinstance(cards, list):
        return []
    return [c for c in cards if isinstance(c, dict)][:limit]


def main() -> int:
    parser = argparse.ArgumentParser(description="Print VulnScope JARVIS-style run summary")
    parser.add_argument("--target", default="authorized target")
    parser.add_argument("--limit", type=int, default=8)
    args = parser.parse_args()
    loaded = {name: load(path) for name, path in REPORTS.items()}

    print("\n╔════════════════════════════════════════════════════════════════════╗")
    print("║                 VULNSCOPE JARVIS RUN SUMMARY                     ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print(f"Target: {args.target}\n")

    tm = loaded.get("tool_mind") or {}
    if tm:
        s = tm.get("summary", {})
        print(f"[TOOLS] Desired={s.get('desired', 0)} Installed={s.get('installed', 0)} Missing={s.get('missing', 0)}")
        missing = [t for t in tm.get("tools", []) if not t.get("installed_after")][:8]
        if missing:
            print("[TOOLS] Still missing:")
            for item in missing:
                print(f"  - {item.get('name')} | decision={item.get('decision')}")

    pr = loaded.get("tool_path_repair") or {}
    if pr:
        s = pr.get("summary", {})
        print(f"[PATH] Repaired/found={s.get('repaired_or_found', 0)} Missing={s.get('missing', 0)}")

    norm = loaded.get("normalized") or {}
    if norm:
        s = norm.get("summary", {})
        print(f"[EVIDENCE] Hosts={s.get('hosts', 0)} Endpoints={s.get('endpoints', 0)} Params={s.get('parameters', 0)} Candidates={s.get('candidates', 0)}")

    api = loaded.get("api_intel") or {}
    if api:
        s = api.get("summary", {})
        print(f"[API] API endpoints={s.get('api_endpoints', 0)} GraphQL={s.get('graphql', 0)} Object/Auth review={s.get('object_review', 0)}")

    print("\n[FINDINGS / REVIEW CARDS]")
    cards = pick_cards(loaded.get("evidence_cards"), args.limit)
    if not cards:
        cards = pick_cards(loaded.get("reportability"), args.limit)
    if not cards:
        print("  No evidence cards yet. Run full review or advanced modes first.")
    for idx, card in enumerate(cards, 1):
        title = card.get("title") or card.get("category") or "Review item"
        where = card.get("where_found") or card.get("url") or card.get("endpoint") or "n/a"
        why = card.get("why_flagged") or card.get("why_found") or card.get("reportability_reasons") or "Evidence correlation flagged this item."
        safe_check = card.get("safe_check") or card.get("how_to_check_safely") or "Review manually on owned/authorized assets."
        print(f"\n  {idx}. {title}")
        print(f"     Where : {where}")
        print(f"     Why   : {why}")
        print(f"     Next  : {safe_check}")

    print("\n[NEXT ACTION]")
    if tm and tm.get("summary", {}).get("missing", 0):
        print("  Run: python3 tool_path_repair_cli.py")
        print("  Then: source ~/.zshrc")
    elif not cards:
        print("  Run: python3 vulnscope_cli.py -> option 1 or 14")
    else:
        print("  Open: reports/output/evidence-cards/evidence-cards.md")
        print("  Then validate only the high-confidence cards manually.")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
