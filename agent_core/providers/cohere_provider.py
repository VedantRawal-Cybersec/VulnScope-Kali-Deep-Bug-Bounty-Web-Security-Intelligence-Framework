from __future__ import annotations

from typing import Any

from agent_core.providers.base_provider import BaseProvider, ProviderResponse, join_messages


class CohereProvider(BaseProvider):
    provider_name = "cohere"
    env_key = "COHERE_API_KEY"
    default_model = "command-r-plus"
    base_url = "https://api.cohere.com/v2/chat"

    def chat(self, messages: list[dict[str, str]], temperature: float = 0.1, max_tokens: int = 1200) -> ProviderResponse:
        if not self.api_key:
            return ProviderResponse(self.provider_name, self.model, False, "", error="COHERE_API_KEY is not configured")
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages if messages else [{"role": "user", "content": "Review the provided evidence."}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        ok, data, error = self._post_json(
            self.base_url,
            {"authorization": f"Bearer {self.api_key}", "content-type": "application/json"},
            payload,
        )
        if not ok or data is None:
            legacy_payload = {
                "model": self.model,
                "message": join_messages(messages),
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            ok2, data2, error2 = self._post_json(
                "https://api.cohere.ai/v1/chat",
                {"authorization": f"Bearer {self.api_key}", "content-type": "application/json"},
                legacy_payload,
            )
            if not ok2 or data2 is None:
                return ProviderResponse(self.provider_name, self.model, False, "", error=error2 or error)
            return ProviderResponse(self.provider_name, self.model, True, data2.get("text", ""), raw=data2)
        text = ""
        message = data.get("message", {})
        content = message.get("content", []) if isinstance(message, dict) else []
        if isinstance(content, list):
            text = "\n".join(part.get("text", "") for part in content if isinstance(part, dict))
        if not text:
            text = data.get("text", "")
        return ProviderResponse(self.provider_name, self.model, True, text, raw=data)
