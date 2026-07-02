#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict

from vulnscope_preflight import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL, check_ollama


@dataclass
class OllamaStatus:
    reachable: bool = False
    model: str = ""
    label: str = "Not checked"
    error: str = ""
    detail: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def run_ollama_diagnostics(generate_url: str | None = None, model: str | None = None) -> OllamaStatus:
    generate_url = generate_url or os.getenv("VULNSCOPE_OLLAMA_URL", DEFAULT_OLLAMA_URL)
    model = model or os.getenv("VULNSCOPE_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
    try:
        payload = check_ollama(generate_url=generate_url, model=model, auto_pull_model=False)
        ok = bool(payload.get("ok"))
        service = str(payload.get("service") or "unknown")
        label = f"Connected • {model} • reasoning enabled" if ok else f"Fallback • {model} • {service}"
        return OllamaStatus(reachable=service == "running", model=model, label=label, error="" if ok else str(payload.get("service_detail") or "not ready")[:500], detail=payload)
    except Exception as exc:
        return OllamaStatus(reachable=False, model=model, label=f"Fallback • {model} • diagnostics error", error=str(exc)[:500], detail={})


def main() -> int:
    status = run_ollama_diagnostics()
    print(json.dumps(status.to_dict(), indent=2, ensure_ascii=False))
    return 0 if status.reachable else 1


if __name__ == "__main__":
    raise SystemExit(main())
