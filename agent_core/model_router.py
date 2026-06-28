from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class ModelRoute:
    provider: str
    model: str
    reason: str
    available: bool


def choose_model(task_type: str = "review") -> ModelRoute:
    available = {
        "openai": bool(os.getenv("OPENAI_API_KEY")),
        "gemini": bool(os.getenv("GEMINI_API_KEY")),
        "groq": bool(os.getenv("GROQ_API_KEY")),
        "openrouter": bool(os.getenv("OPENROUTER_API_KEY")),
    }
    if task_type in {"deep_review", "report"} and available["openai"]:
        return ModelRoute("openai", "configured-default", "best available route for deep review/report generation", True)
    if available["gemini"]:
        return ModelRoute("gemini", "configured-default", "available route for broad context review", True)
    if available["groq"]:
        return ModelRoute("groq", "configured-default", "available route for fast review", True)
    if available["openrouter"]:
        return ModelRoute("openrouter", "configured-default", "available route through OpenRouter", True)
    return ModelRoute("local-rules", "no-api-key", "no AI provider key configured; using deterministic local review", False)


def provider_status() -> dict[str, bool]:
    return {
        "openai": bool(os.getenv("OPENAI_API_KEY")),
        "gemini": bool(os.getenv("GEMINI_API_KEY")),
        "groq": bool(os.getenv("GROQ_API_KEY")),
        "openrouter": bool(os.getenv("OPENROUTER_API_KEY")),
    }
