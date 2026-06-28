from __future__ import annotations

import os
from typing import Any

from agent_core.model_router import choose_model, provider_status
from agent_core.prompt_firewall import sanitize_evidence_for_ai
from agent_core.providers.anthropic_provider import AnthropicProvider
from agent_core.providers.base_provider import BaseProvider, ProviderResponse
from agent_core.providers.ollama_provider import OllamaProvider
from agent_core.providers.openai_compatible_provider import DeepSeekProvider, GroqProvider, OpenAIProvider, OpenRouterProvider

PROVIDER_CLASSES: dict[str, type[BaseProvider]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "claude": AnthropicProvider,
    "deepseek": DeepSeekProvider,
    "groq": GroqProvider,
    "openrouter": OpenRouterProvider,
    "ollama": OllamaProvider,
}

PROVIDER_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "claude": "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "groq": "GROQ_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "ollama": "OLLAMA_HOST",
}

PROVIDER_MODEL_ENV: dict[str, str] = {
    "openai": "OPENAI_MODEL",
    "anthropic": "ANTHROPIC_MODEL",
    "claude": "ANTHROPIC_MODEL",
    "deepseek": "DEEPSEEK_MODEL",
    "groq": "GROQ_MODEL",
    "openrouter": "OPENROUTER_MODEL",
    "ollama": "OLLAMA_MODEL",
}


def get_provider(provider_name: str | None = None, task_type: str = "deep_review") -> BaseProvider:
    selected = provider_name or choose_model(task_type).provider
    selected = selected.lower()
    provider_cls = PROVIDER_CLASSES.get(selected)
    if not provider_cls:
        provider_cls = OllamaProvider
        selected = "ollama"
    env_key = PROVIDER_ENV.get(selected, "")
    model_env = PROVIDER_MODEL_ENV.get(selected, "")
    api_key = os.getenv(env_key) if env_key else None
    model = os.getenv(model_env) if model_env else None
    return provider_cls(api_key=api_key, model=model)


def safe_chat(prompt: str, provider_name: str | None = None, task_type: str = "deep_review", system: str | None = None) -> ProviderResponse:
    provider = get_provider(provider_name, task_type=task_type)
    clean_prompt = sanitize_evidence_for_ai(prompt)
    messages = []
    if system:
        messages.append({"role": "system", "content": sanitize_evidence_for_ai(system)})
    messages.append({"role": "user", "content": clean_prompt})
    return provider.chat(messages)


def provider_report() -> dict[str, Any]:
    return {
        "available": provider_status(),
        "configured_provider_names": sorted(PROVIDER_CLASSES.keys()),
        "env_keys": PROVIDER_ENV,
        "model_env_keys": PROVIDER_MODEL_ENV,
        "note": "Keys are read locally from environment variables only. Do not commit or paste secrets.",
    }
