#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

PROFILE_PATH = Path("config/deep_scan_profile.json")


def normalize_target(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        raise SystemExit("Target is required. Example: python3 vulnscope_deep.py https://example.com")
    return value if "://" in value else "https://" + value


def host(url: str) -> str:
    return (urlparse(normalize_target(url)).hostname or "").lower()


def load_profile() -> dict:
    if PROFILE_PATH.exists():
        return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    return {
        "scan_mode": "bugbounty",
        "include_subdomains": True,
        "browser": True,
        "max_pages": 350,
        "max_depth": 5,
        "max_params": 600,
        "request_timeout": 12,
        "delay": 0.25,
        "request_budget": 2500,
        "max_actions": 320,
        "asset_doc_limit": 80,
        "llm_decision_interval": 3,
    }


def ask_authorization(target: str, yes: bool) -> None:
    print("\nVulnScope Deep Scan")
    print("Target: " + target)
    print("Scope: exact host and, by default, same parent-domain subdomains when discovered.")
    print("Rules: owned/authorized websites only; no credential attacks; no destructive actions; no data modification.")
    if yes or os.getenv("VULNSCOPE_AUTHORIZED", "0") == "1":
        return
    answer = input("\nDo you have explicit written authorization to test this target? (yes/no): ").strip().lower()
    if answer not in {"yes", "y"}:
        raise SystemExit("Authorization not confirmed. Scan stopped.")


def run_json(command: list[str], *, env: dict[str, str] | None = None) -> tuple[int, dict]:
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, timeout=90)
    except subprocess.TimeoutExpired:
        return 124, {"ok": False, "error": "diagnostic timeout"}
    text = proc.stdout.strip()
    try:
        payload = json.loads(text[text.find("{"):]) if "{" in text else {}
    except Exception:
        payload = {"raw_stdout": proc.stdout[-3000:], "raw_stderr": proc.stderr[-3000:]}
    return proc.returncode, payload


def normalize_seed(target: str, seed: str) -> str:
    seed = str(seed or "").strip()
    if not seed:
        return ""
    if "://" in seed:
        return seed
    return target.rstrip("/") + "/" + seed.lstrip("/")


def same_scope_seeds(target: str, seeds: list[str]) -> list[str]:
    target_host = host(target)
    output: list[str] = []
    for seed in seeds:
        url = normalize_seed(target, seed)
        if not url:
            continue
        if host(url) == target_host:
            output.append(url)
        else:
            print("Ignoring out-of-scope seed URL: " + url, file=sys.stderr)
    return output


def build_command(target: str, args: argparse.Namespace, profile: dict) -> list[str]:
    cmd = [
        sys.executable,
        "vulnscope.py",
        "--target",
        target,
        "--mode",
        args.mode or str(profile.get("scan_mode", "bugbounty")),
        "--max-pages",
        str(args.max_pages or profile.get("max_pages", 350)),
        "--max-depth",
        str(args.max_depth or profile.get("max_depth", 5)),
        "--max-params",
        str(args.max_params or profile.get("max_params", 600)),
        "--request-timeout",
        str(args.request_timeout or profile.get("request_timeout", 12)),
        "--delay",
        str(args.delay if args.delay is not None else profile.get("delay", 0.25)),
        "--request-budget",
        str(args.request_budget or profile.get("request_budget", 2500)),
        "--max-actions",
        str(args.max_actions or profile.get("max_actions", 320)),
        "--asset-doc-limit",
        str(args.asset_doc_limit or profile.get("asset_doc_limit", 80)),
    ]
    if profile.get("include_subdomains", True) and not args.no_subdomains:
        cmd.append("--include-subdomains")
    if profile.get("browser", True) and not args.no_browser:
        cmd.append("--browser")
    if args.no_dynamic_tools:
        cmd.append("--no-dynamic-tools")
    if args.no_live_dashboard:
        cmd.append("--no-live-dashboard")
    if args.yes:
        cmd.append("--yes")
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description="One-command deep VulnScope scan for owned/authorized websites.")
    parser.add_argument("target", help="Target URL/domain. Example: https://example.com")
    parser.add_argument("--mode", choices=["bugbounty", "lab"], default="")
    parser.add_argument("--seed-url", action="append", default=[], help="Optional same-scope URL/path with existing query parameters. Repeatable.")
    parser.add_argument("--yes", action="store_true", help="Skip authorization prompt only if written authorization is already confirmed.")
    parser.add_argument("--skip-network-diag", action="store_true")
    parser.add_argument("--continue-if-unreachable", action="store_true", help="Continue only when you supplied seed URLs and understand network checks failed.")
    parser.add_argument("--no-subdomains", action="store_true")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--no-dynamic-tools", action="store_true")
    parser.add_argument("--no-live-dashboard", action="store_true")
    parser.add_argument("--max-pages", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--max-depth", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--max-params", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--request-timeout", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--delay", type=float, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--request-budget", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--max-actions", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--asset-doc-limit", type=int, default=0, help=argparse.SUPPRESS)
    args = parser.parse_args()

    target = normalize_target(args.target)
    profile = load_profile()
    ask_authorization(target, args.yes)

    seeds = same_scope_seeds(target, args.seed_url)
    env = os.environ.copy()
    if seeds:
        existing = env.get("VULNSCOPE_SEED_URLS", "").strip()
        env["VULNSCOPE_SEED_URLS"] = ",".join([value for value in [existing, *seeds] if value])
    env.setdefault("VULNSCOPE_LLM_DECISION_INTERVAL", str(profile.get("llm_decision_interval", 3)))

    if not args.skip_network_diag:
        print("\n[1/3] Checking target reachability...")
        code, payload = run_json([sys.executable, "scripts/network_diag.py", "--target", target, "--timeout", str(profile.get("request_timeout", 12))], env=env)
        reachable = bool(payload.get("http", {}).get("ok"))
        if not reachable:
            print("Target reachability failed. See logs/network_diagnostics.json")
            print(json.dumps(payload.get("recommendations", []), indent=2))
            if not (args.continue_if_unreachable and seeds):
                print("Stopping before scan because the target is unreachable from this machine.")
                print("Fix DNS/proxy/VPN/firewall or provide reachable same-scope seed URLs and --continue-if-unreachable.")
                return 2
        else:
            print("Target reachable. Continuing.")

    print("\n[2/3] Preparing deep safe-active workflow...")
    if seeds:
        print("Seed URLs:")
        for seed in seeds:
            print("  - " + seed)
    else:
        print("No seed URLs supplied. VulnScope will rely on crawler, subdomain discovery, JS mining, forms, and parameter inventory.")

    print("\n[3/3] Launching VulnScope...")
    cmd = build_command(target, args, profile)
    print("$ " + " ".join(cmd))
    started = time.time()
    exit_code = subprocess.call(cmd, env=env)
    print(f"\nFinished with exit code {exit_code} in {int(time.time() - started)}s")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
