from __future__ import annotations

import getpass
import os
from pathlib import Path

from ai.local_env import configured_key_status

KEYS = [
    ("OPENAI_API_KEY", "OpenAI API key"),
    ("GEMINI_API_KEY", "Google Gemini API key"),
    ("GROQ_API_KEY", "Groq API key"),
    ("OPENROUTER_API_KEY", "OpenRouter API key"),
]

DEFAULT_ENV_PATH = Path(".env.local")


def setup_ai_keys(output_path: str = ".env.local") -> None:
    """Interactive local API key setup.

    Keys are written only to a local ignored file. They are never printed after
    entry and should never be committed to GitHub.
    """
    path = Path(output_path)

    print("\n┌──────────────────────────── AI Key Setup ────────────────────────────┐")
    print("│ Add API keys locally for the AI Analyst Engine.                       │")
    print("│ Keys will be saved only on this machine.                              │")
    print("│ Default file: .env.local                                               │")
    print("│ Leave a field empty to skip that provider.                            │")
    print("└──────────────────────────────────────────────────────────────────────┘")

    existing = _read_existing_env(path)
    values: dict[str, str] = dict(existing)

    for env_name, label in KEYS:
        already_set = bool(os.getenv(env_name) or existing.get(env_name))
        suffix = " [already configured, press Enter to keep]" if already_set else ""
        entered = getpass.getpass(f"{label}{suffix}: ").strip()
        if entered:
            values[env_name] = entered

    lines = [
        "# VulnScope-Kali local AI provider keys",
        "# This file is ignored by git. Do not commit real secrets.",
        "",
    ]
    for env_name, _label in KEYS:
        value = values.get(env_name, "")
        if value:
            lines.append(f'{env_name}="{_escape_env_value(value)}"')

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    print(f"\n[+] AI keys saved locally to: {path}")
    print("[+] File permission set to owner-read/write where supported.")
    print("[+] Run: python3 vulnscope.py --ai-key-status")
    print("[+] Then run: python3 vulnscope.py --url https://example.com --mode passive --ai-review")


def show_ai_key_status() -> None:
    status = configured_key_status()
    print("\nAI Provider Key Status")
    print("──────────────────────")
    for key, configured in status.items():
        state = "configured" if configured else "missing"
        print(f"{key:<22} {state}")
    print("\nNo key values are displayed for safety.")


def _read_existing_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _escape_env_value(value: str) -> str:
    return value.replace('\\', '\\\\').replace('"', '\\"')


if __name__ == "__main__":
    setup_ai_keys()
