from __future__ import annotations

import os
from typing import Any

from agent_core.providers.base_provider import BaseProvider, ProviderResponse, join_messages


class OllamaProvider(BaseProvider):
    provider_name = "ollama"
    env_key = "OLLAMA_HOST"
    default_model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder")

    def __init__(self, api_key: str | None = None, model: str | None = None, timeout: int = 120) -> None:
        super().__init__(api_key=api_key, model=model or self.default_model, timeout=timeout)
        self.host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")

    def is_configured(self) -> bool:
        return True

    def chat(self, messages: list[dict[str, str]], temperature: float = 0.1, max_tokens: int = 1200) -> ProviderResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": join_messages(messages),
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        ok, data, error = self._post_json(f"{self.host}/api/generate", {"content-type": "application/json"}, payload)
        if not ok or data is None:
            return ProviderResponse(self.provider_name, self.model, False, "", error=error)
        return ProviderResponse(self.provider_name, self.model, True, data.get("response", ""), raw=data)
