from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class ModelRoute:
    provider: str
    model: str
    reason: str
    available: bool


PROVIDER_ENV = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "cohere": "COHERE_API_KEY",
    "together": "TOGETHER_API_KEY",
    "fireworks": "FIREWORKS_API_KEY",
    "perplexity": "PERPLEXITY_API_KEY",
}


def provider_status() -> dict[str, bool]:
    status = {name: bool(os.getenv(env)) for name, env in PROVIDER_ENV.items()}
    status["ollama"] = bool(os.getenv("OLLAMA_HOST", "http://localhost:11434"))
    status["local-rules"] = True
    return status


def choose_model(task_type: str = "review") -> ModelRoute:
    available = provider_status()
    priority = _priority_for_task(task_type)
    for provider in priority:
        if available.get(provider):
            return ModelRoute(provider, _default_model(provider), f"selected for {task_type}", True)
    return ModelRoute("local-rules", "deterministic", "no external provider key configured; using local review logic", True)


def _priority_for_task(task_type: str) -> list[str]:
    if task_type in {"deep_review", "report", "reasoning"}:
        return ["openai", "anthropic", "gemini", "deepseek", "openrouter", "mistral", "groq", "ollama", "local-rules"]
    if task_type in {"fast_triage", "bulk_review"}:
        return ["groq", "deepseek", "openrouter", "gemini", "openai", "ollama", "local-rules"]
    if task_type in {"local_private", "sensitive"}:
        return ["ollama", "local-rules"]
    return ["openai", "anthropic", "deepseek", "gemini", "openrouter", "groq", "ollama", "local-rules"]


def _default_model(provider: str) -> str:
    defaults = {
        "openai": os.getenv("OPENAI_MODEL", "configured-default"),
        "anthropic": os.getenv("ANTHROPIC_MODEL", "configured-default"),
        "deepseek": os.getenv("DEEPSEEK_MODEL", "configured-default"),
        "gemini": os.getenv("GEMINI_MODEL", "configured-default"),
        "groq": os.getenv("GROQ_MODEL", "configured-default"),
        "openrouter": os.getenv("OPENROUTER_MODEL", "configured-default"),
        "mistral": os.getenv("MISTRAL_MODEL", "configured-default"),
        "cohere": os.getenv("COHERE_MODEL", "configured-default"),
        "together": os.getenv("TOGETHER_MODEL", "configured-default"),
        "fireworks": os.getenv("FIREWORKS_MODEL", "configured-default"),
        "perplexity": os.getenv("PERPLEXITY_MODEL", "configured-default"),
        "ollama": os.getenv("OLLAMA_MODEL", "llama3.1"),
        "local-rules": "deterministic",
    }
    return defaults.get(provider, "configured-default")


def provider_count_label() -> str:
    return "300+ models via OpenRouter/Ollama-compatible routing plus direct provider keys"
