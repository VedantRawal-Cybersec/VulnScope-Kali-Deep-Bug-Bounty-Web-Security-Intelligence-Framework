from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class ProviderResponse:
    provider: str
    model: str
    ok: bool
    content: str
    raw: dict[str, Any] | None = None
    error: str | None = None


class BaseProvider:
    provider_name = "base"
    env_key = ""
    default_model = "configured-default"
    base_url = ""

    def __init__(self, api_key: str | None = None, model: str | None = None, timeout: int = 60) -> None:
        self.api_key = api_key
        self.model = model or self.default_model
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def chat(self, messages: list[dict[str, str]], temperature: float = 0.1, max_tokens: int = 1200) -> ProviderResponse:
        raise NotImplementedError

    def _post_json(self, url: str, headers: dict[str, str], payload: dict[str, Any]) -> tuple[bool, dict[str, Any] | None, str | None]:
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=self.timeout)
            if response.status_code >= 400:
                return False, None, f"HTTP {response.status_code}: {response.text[:500]}"
            return True, response.json(), None
        except Exception as exc:
            return False, None, str(exc)


def join_messages(messages: list[dict[str, str]]) -> str:
    return "\n\n".join(f"{m.get('role', 'user').upper()}: {m.get('content', '')}" for m in messages)
