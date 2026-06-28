from __future__ import annotations

import os
from pathlib import Path

LOCAL_ENV_PATHS = [
    Path('.env.local'),
    Path.home() / '.vulnscope' / 'ai.env',
]


def load_local_ai_env() -> list[str]:
    """Load local AI provider keys from ignored local env files.

    Existing process environment variables always win. This helper never prints
    or returns secret values; it only returns the paths that were loaded.
    """
    loaded: list[str] = []
    for path in LOCAL_ENV_PATHS:
        if not path.exists() or not path.is_file():
            continue
        for line in path.read_text(encoding='utf-8').splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or '=' not in stripped:
                continue
            key, value = stripped.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value and key not in os.environ:
                os.environ[key] = value
        loaded.append(str(path))
    return loaded


def configured_key_status() -> dict[str, bool]:
    load_local_ai_env()
    return {
        'OPENAI_API_KEY': bool(os.getenv('OPENAI_API_KEY')),
        'GEMINI_API_KEY': bool(os.getenv('GEMINI_API_KEY')),
        'GROQ_API_KEY': bool(os.getenv('GROQ_API_KEY')),
        'OPENROUTER_API_KEY': bool(os.getenv('OPENROUTER_API_KEY')),
    }
