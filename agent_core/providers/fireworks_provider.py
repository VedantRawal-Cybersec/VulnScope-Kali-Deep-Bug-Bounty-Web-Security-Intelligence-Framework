from __future__ import annotations

from agent_core.providers.openai_compatible_provider import OpenAICompatibleProvider


class FireworksProvider(OpenAICompatibleProvider):
    provider_name = "fireworks"
    env_key = "FIREWORKS_API_KEY"
    default_model = "accounts/fireworks/models/llama-v3p1-70b-instruct"
    base_url = "https://api.fireworks.ai/inference/v1/chat/completions"
