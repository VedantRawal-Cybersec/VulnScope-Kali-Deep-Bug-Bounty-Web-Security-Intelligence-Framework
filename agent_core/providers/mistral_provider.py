from __future__ import annotations

from agent_core.providers.openai_compatible_provider import OpenAICompatibleProvider


class MistralProvider(OpenAICompatibleProvider):
    provider_name = "mistral"
    env_key = "MISTRAL_API_KEY"
    default_model = "mistral-large-latest"
    base_url = "https://api.mistral.ai/v1/chat/completions"
