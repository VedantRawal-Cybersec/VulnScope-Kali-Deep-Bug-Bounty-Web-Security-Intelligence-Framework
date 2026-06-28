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
    parser.add_argument("--provider", default="anthropic", help="Provider name: anthropic/claude/deepseek/openai/groq/openrouter/ollama/mistral/fireworks/cohere")
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
    aliases = {"claude": "anthropic", "firework": "fireworks"}
    provider = aliases.get(provider, provider)
    env_map = {
        "anthropic": "ANTHROPIC_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "openai": "OPENAI_API_KEY",
        "groq": "GROQ_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "mistral": "MISTRAL_API_KEY",
        "fireworks": "FIREWORKS_API_KEY",
        "cohere": "COHERE_API_KEY",
        "together": "TOGETHER_API_KEY",
        "perplexity": "PERPLEXITY_API_KEY",
    }
    model_env_map = {
        "anthropic": "ANTHROPIC_MODEL",
        "deepseek": "DEEPSEEK_MODEL",
        "openai": "OPENAI_MODEL",
        "groq": "GROQ_MODEL",
        "openrouter": "OPENROUTER_MODEL",
        "mistral": "MISTRAL_MODEL",
        "fireworks": "FIREWORKS_MODEL",
        "cohere": "COHERE_MODEL",
        "together": "TOGETHER_MODEL",
        "perplexity": "PERPLEXITY_MODEL",
        "ollama": "OLLAMA_MODEL",
    }
    default_models = {
        "mistral": "mistral-large-latest",
        "fireworks": "accounts/fireworks/models/llama-v3p1-70b-instruct",
        "cohere": "command-r-plus",
        "together": "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        "perplexity": "sonar",
    }
    if provider == "ollama":
        host = input("OLLAMA_HOST [http://localhost:11434]: ").strip() or "http://localhost:11434"
        append_env("OLLAMA_HOST", host)
        append_env("OLLAMA_MODEL", model or "qwen2.5-coder")
        print("[+] Saved Ollama settings to .env.local")
        return
    env_key = env_map.get(provider)
    if not env_key:
        print(f"[!] Unsupported provider for setup: {provider}")
        print("Supported: anthropic/claude, deepseek, openai, groq, openrouter, ollama, mistral, fireworks, cohere, together, perplexity")
        return
    value = getpass.getpass(f"Enter {env_key}: ").strip()
    if not value:
        print("[!] Empty key, skipped")
        return
    append_env(env_key, value)
    model_key = model_env_map.get(provider)
    model_value = model or default_models.get(provider)
    if model_key and model_value:
        append_env(model_key, model_value)
    print(f"[+] Saved {env_key} to .env.local")
    if model_key and model_value:
        print(f"[+] Saved {model_key}={model_value}")
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
