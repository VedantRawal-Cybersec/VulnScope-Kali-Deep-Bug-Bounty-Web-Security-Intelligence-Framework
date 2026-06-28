from __future__ import annotations

from typing import Any

from agent_core.providers.base_provider import BaseProvider, ProviderResponse


class AnthropicProvider(BaseProvider):
    provider_name = "anthropic"
    env_key = "ANTHROPIC_API_KEY"
    default_model = "claude-3-5-sonnet-latest"
    base_url = "https://api.anthropic.com/v1/messages"

    def chat(self, messages: list[dict[str, str]], temperature: float = 0.1, max_tokens: int = 1200) -> ProviderResponse:
        if not self.api_key:
            return ProviderResponse(self.provider_name, self.model, False, "", error="ANTHROPIC_API_KEY is not configured")

        system_parts: list[str] = []
        user_messages: list[dict[str, str]] = []
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            if role == "system":
                system_parts.append(content)
            elif role in {"user", "assistant"}:
                user_messages.append({"role": role, "content": content})
            else:
                user_messages.append({"role": "user", "content": content})

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": user_messages or [{"role": "user", "content": "Review the provided evidence."}],
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)

        ok, data, error = self._post_json(
            self.base_url,
            {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            payload,
        )
        if not ok or data is None:
            return ProviderResponse(self.provider_name, self.model, False, "", error=error)
        content_blocks = data.get("content", [])
        text = "\n".join(block.get("text", "") for block in content_blocks if isinstance(block, dict))
        return ProviderResponse(self.provider_name, self.model, True, text, raw=data)
