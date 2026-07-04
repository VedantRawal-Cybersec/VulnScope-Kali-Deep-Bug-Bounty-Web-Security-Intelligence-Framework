#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from urllib.parse import urlparse


def host(url: str) -> str:
    raw = url if "://" in url else "https://" + url
    return (urlparse(raw).hostname or "").lower()


def normalize_seed(target: str, seed: str) -> str:
    seed = seed.strip()
    if not seed:
        return ""
    if "://" in seed:
        return seed
    return target.rstrip("/") + "/" + seed.lstrip("/")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run VulnScope on an owned/authorized website with optional seed URLs.")
    parser.add_argument("--target", required=True, help="Owned or explicitly authorized target URL/domain.")
    parser.add_argument("--seed-url", action="append", default=[], help="Same-scope path or URL to include as a validation seed. Repeatable.")
    parser.add_argument("--mode", choices=["bugbounty", "lab"], default="bugbounty")
    parser.add_argument("--max-pages", default="80")
    parser.add_argument("--max-depth", default="3")
    parser.add_argument("--max-actions", default="120")
    parser.add_argument("--request-budget", default="400")
    parser.add_argument("--asset-doc-limit", default="12")
    parser.add_argument("--yes", action="store_true", help="Skip interactive authorization prompts only when written authorization is already confirmed.")
    args, extra = parser.parse_known_args()

    target = args.target if "://" in args.target else "https://" + args.target
    target_host = host(target)
    seeds = []
    for item in args.seed_url:
        normalized = normalize_seed(target, item)
        if normalized and host(normalized) == target_host:
            seeds.append(normalized)
        elif normalized:
            print(f"Ignoring out-of-scope seed URL: {normalized}", file=sys.stderr)
    env = os.environ.copy()
    if seeds:
        existing = env.get("VULNSCOPE_SEED_URLS", "").strip()
        env["VULNSCOPE_SEED_URLS"] = ",".join([value for value in [existing, *seeds] if value])
    env["VULNSCOPE_DISABLE_LLM_PLANNER"] = env.get("VULNSCOPE_DISABLE_LLM_PLANNER", "1")

    cmd = [
        sys.executable,
        "vulnscope.py",
        "--target",
        target,
        "--mode",
        args.mode,
        "--max-pages",
        str(args.max_pages),
        "--max-depth",
        str(args.max_depth),
        "--max-actions",
        str(args.max_actions),
        "--request-budget",
        str(args.request_budget),
        "--asset-doc-limit",
        str(args.asset_doc_limit),
    ]
    if args.yes:
        cmd.append("--yes")
    cmd.extend(extra)
    print("Running: " + " ".join(cmd))
    if seeds:
        print("Seed URLs:")
        for seed in seeds:
            print("  - " + seed)
    return subprocess.call(cmd, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
