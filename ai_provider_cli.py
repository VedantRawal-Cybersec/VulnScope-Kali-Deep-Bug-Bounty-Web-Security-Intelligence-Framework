#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path

from agent_core.providers.provider_manager import provider_report, safe_chat

ENV_PATH = Path(".env.local")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Configure and test VulnScope AI providers")
    parser.add_argument("--status", action="store_true", help="Show provider configuration status")
    parser.add_argument("--setup", action="store_true", help="Interactively save provider keys to .env.local")
    parser.add_argument("--test", action="store_true", help="Send a short safe test prompt")
    parser.add_argument("--provider", default="anthropic", help="Provider name: anthropic/claude/deepseek/openai/groq/openrouter/ollama")
    parser.add_argument("--model", help="Optional model name to save during setup")
    return parser.parse_args()


def load_local_env() -> None:
    if not ENV_PATH.exists():
        return
    for line in ENV_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def append_env(key: str, value: str) -> None:
    ENV_PATH.touch(exist_ok=True)
    existing = ENV_PATH.read_text(encoding="utf-8", errors="ignore")
    lines = [line for line in existing.splitlines() if not line.startswith(f"{key}=")]
    lines.append(f"{key}={value}")
    ENV_PATH.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")


def setup_provider(provider: str, model: str | None) -> None:
    provider = provider.lower()
    if provider == "claude":
        provider = "anthropic"
    env_map = {
        "anthropic": "ANTHROPIC_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "openai": "OPENAI_API_KEY",
        "groq": "GROQ_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
    }
    model_env_map = {
        "anthropic": "ANTHROPIC_MODEL",
        "deepseek": "DEEPSEEK_MODEL",
        "openai": "OPENAI_MODEL",
        "groq": "GROQ_MODEL",
        "openrouter": "OPENROUTER_MODEL",
        "ollama": "OLLAMA_MODEL",
    }
    if provider == "ollama":
        host = input("OLLAMA_HOST [http://localhost:11434]: ").strip() or "http://localhost:11434"
        append_env("OLLAMA_HOST", host)
        if model:
            append_env("OLLAMA_MODEL", model)
        print("[+] Saved Ollama settings to .env.local")
        return
    env_key = env_map.get(provider)
    if not env_key:
        print(f"[!] Unsupported provider for setup: {provider}")
        return
    value = getpass.getpass(f"Enter {env_key}: ").strip()
    if not value:
        print("[!] Empty key, skipped")
        return
    append_env(env_key, value)
    model_key = model_env_map.get(provider)
    if model and model_key:
        append_env(model_key, model)
    print(f"[+] Saved {env_key} to .env.local")
    print("[!] Keep .env.local private. Never commit or paste it.")


def main() -> int:
    args = parse_args()
    load_local_env()
    if args.setup:
        setup_provider(args.provider, args.model)
        return 0
    if args.status:
        report = provider_report()
        print("Provider availability:")
        for name, available in report["available"].items():
            print(f"- {name}: {'configured' if available else 'missing'}")
        return 0
    if args.test:
        response = safe_chat(
            "Reply with one short sentence: VulnScope AI provider is configured.",
            provider_name=args.provider,
            system="You are a safe cybersecurity workflow assistant. Do not request secrets.",
        )
        if response.ok:
            print(f"[+] {response.provider}/{response.model}: {response.content.strip()}")
            return 0
        print(f"[!] Provider test failed: {response.error}")
        return 1
    print("Use --status, --setup, or --test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
