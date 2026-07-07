#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

try:
    import ollama  # type: ignore
except Exception as exc:  # pragma: no cover - depends on local environment
    ollama = None  # type: ignore
    OLLAMA_IMPORT_ERROR = str(exc)
else:
    OLLAMA_IMPORT_ERROR = ""


def ollama_health(*, host: str | None = None, model: str | None = None, write: bool = True) -> dict[str, Any]:
    host = (host or os.getenv("OLLAMA_HOST") or "http://192.168.199.1:11434").rstrip("/")
    model = model or os.getenv("VULNSCOPE_OLLAMA_MODEL") or "deepseek-local"
    payload: dict[str, Any] = {"ok": False, "host": host, "model": model, "available_models": [], "selected_model": model, "error": "", "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if ollama is None:
        payload["error"] = "Python package 'ollama' is not installed. Install with: pip install ollama. Continuing is allowed only when --allow-ai-fallback is used."
        payload["import_error"] = OLLAMA_IMPORT_ERROR
        if write:
            out = Path("logs/ai-health.json")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return payload
    try:
        client = ollama.Client(host=host)
        listed = client.list()
        raw = listed.get("models", []) if isinstance(listed, dict) else getattr(listed, "models", [])
        names: list[str] = []
        for item in raw:
            name = item.get("name") if isinstance(item, dict) else getattr(item, "name", "")
            if name:
                names.append(str(name))
        payload["available_models"] = names
        if names and model not in names:
            prefix = model.split(":", 1)[0]
            matches = [name for name in names if name.split(":", 1)[0] == prefix or prefix in name]
            if matches:
                payload["selected_model"] = matches[0]
                payload["model_fallback"] = matches[0]
                payload["ok"] = True
            else:
                payload["error"] = f"model not found: {model}"
        else:
            payload["ok"] = True
        if payload["ok"]:
            reply = client.chat(model=payload["selected_model"], messages=[{"role": "user", "content": "Reply with OK only."}], options={"temperature": 0})
            text = str(reply.get("message", {}).get("content", "")).strip()
            payload["sample_reply"] = text[:80]
            if not text:
                payload["ok"] = False
                payload["error"] = "empty model reply"
    except Exception as exc:
        payload["error"] = str(exc)
    if write:
        out = Path("logs/ai-health.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


if __name__ == "__main__":
    print(json.dumps(ollama_health(), indent=2, ensure_ascii=False))
