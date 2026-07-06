#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys


def parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--scope-file", default="")
    parser.add_argument("--auth-profiles-file", default="")
    parser.add_argument("--api-seed", action="append", default=[])
    parser.add_argument("--write-scope-template", nargs="?", const="scope.example.yml", default="")
    parser.add_argument("--write-auth-template", nargs="?", const="auth-profiles.example.json", default="")
    return parser.parse_known_args(argv)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    args, remaining = parse_args(argv)
    if args.write_scope_template:
        from core.scope_config import write_scope_template
        print(write_scope_template(args.write_scope_template))
        return 0
    if args.write_auth_template:
        from core.auth_session import write_auth_template
        print(write_auth_template(args.write_auth_template))
        return 0
    if args.scope_file:
        from core.scope_config import load_scope_config
        cfg = load_scope_config(args.scope_file)
        os.environ["VULNSCOPE_SCOPE_FILE"] = args.scope_file
        os.environ["VULNSCOPE_SCOPE_CONFIG"] = str(cfg.to_dict())
        if cfg.auth_profiles_file and not args.auth_profiles_file:
            args.auth_profiles_file = cfg.auth_profiles_file
        if cfg.api_seeds or cfg.seed_urls:
            args.api_seed.extend(cfg.api_seeds + cfg.seed_urls)
        if cfg.target and not any(item in {"--target", "--url"} for item in remaining):
            remaining.extend(["--target", cfg.target])
        if cfg.include_subdomains and "--include-subdomains" not in remaining:
            remaining.append("--include-subdomains")
        if cfg.mode == "lab" and "--lab-mode" not in remaining:
            remaining.append("--lab-mode")
        for header in cfg.headers:
            remaining.extend(["--header", header])
    if args.auth_profiles_file:
        os.environ["VULNSCOPE_AUTH_PROFILES_FILE"] = args.auth_profiles_file
    if args.api_seed:
        os.environ["VULNSCOPE_API_SEEDS"] = ",".join(args.api_seed)
    from core.deepseek_cli import main as deepseek_main
    return deepseek_main(remaining)


if __name__ == "__main__":
    raise SystemExit(main())
