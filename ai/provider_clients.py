from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class AIProviderResult:
    provider: str
    ok: bool
    text: str
    error: str | None = None


class AIProviderClient:
    def __init__(self, timeout: int = 45) -> None:
        self.timeout = timeout

    def call(self, provider: str, prompt: str) -> AIProviderResult:
        provider = provider.lower().strip()
        if provider == "openai":
            return self._call_openai(prompt)
        if provider == "gemini":
            return self._call_gemini(prompt)
        if provider == "groq":
            return self._call_openai_compatible(
                provider="groq",
                env_key="GROQ_API_KEY",
                base_url="https://api.groq.com/openai/v1/chat/completions",
                model_env="GROQ_MODEL",
                default_model="llama-3.3-70b-versatile",
                prompt=prompt,
            )
        if provider == "openrouter":
            return self._call_openai_compatible(
                provider="openrouter",
                env_key="OPENROUTER_API_KEY",
                base_url="https://openrouter.ai/api/v1/chat/completions",
                model_env="OPENROUTER_MODEL",
                default_model="openai/gpt-4o-mini",
                prompt=prompt,
            )
        return AIProviderResult(provider=provider, ok=False, text="", error="Unsupported provider")

    def _call_openai(self, prompt: str) -> AIProviderResult:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return AIProviderResult(provider="openai", ok=False, text="", error="OPENAI_API_KEY is not set")
        model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
        payload = {
            "model": model,
            "input": prompt,
            "temperature": 0.1,
        }
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        try:
            response = requests.post(
                "https://api.openai.com/v1/responses",
                headers=headers,
                json=payload,
                timeout=self.timeout,
            )
            if response.status_code >= 400:
                return AIProviderResult("openai", False, "", f"HTTP {response.status_code}: {response.text[:400]}")
            data = response.json()
            text = self._extract_openai_response_text(data)
            return AIProviderResult("openai", True, text)
        except requests.RequestException as exc:
            return AIProviderResult("openai", False, "", str(exc))

    def _call_gemini(self, prompt: str) -> AIProviderResult:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return AIProviderResult(provider="gemini", ok=False, text="", error="GEMINI_API_KEY is not set")
        model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.1}}
        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
            if response.status_code >= 400:
                return AIProviderResult("gemini", False, "", f"HTTP {response.status_code}: {response.text[:400]}")
            data = response.json()
            candidates = data.get("candidates", [])
            if not candidates:
                return AIProviderResult("gemini", True, "{}")
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "\n".join(part.get("text", "") for part in parts if part.get("text"))
            return AIProviderResult("gemini", True, text)
        except requests.RequestException as exc:
            return AIProviderResult("gemini", False, "", str(exc))

    def _call_openai_compatible(
        self,
        provider: str,
        env_key: str,
        base_url: str,
        model_env: str,
        default_model: str,
        prompt: str,
    ) -> AIProviderResult:
        api_key = os.getenv(env_key)
        if not api_key:
            return AIProviderResult(provider=provider, ok=False, text="", error=f"{env_key} is not set")
        model = os.getenv(model_env, default_model)
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a defensive security analyst. Return compact JSON only."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        }
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        if provider == "openrouter":
            site_url = os.getenv("OPENROUTER_SITE_URL")
            app_name = os.getenv("OPENROUTER_APP_NAME", "VulnScope-Kali")
            if site_url:
                headers["HTTP-Referer"] = site_url
            headers["X-Title"] = app_name
        try:
            response = requests.post(base_url, headers=headers, json=payload, timeout=self.timeout)
            if response.status_code >= 400:
                return AIProviderResult(provider, False, "", f"HTTP {response.status_code}: {response.text[:400]}")
            data = response.json()
            choices = data.get("choices", [])
            if not choices:
                return AIProviderResult(provider, True, "{}")
            text = choices[0].get("message", {}).get("content", "")
            return AIProviderResult(provider, True, text)
        except requests.RequestException as exc:
            return AIProviderResult(provider, False, "", str(exc))

    @staticmethod
    def _extract_openai_response_text(data: dict[str, Any]) -> str:
        if "output_text" in data:
            return str(data["output_text"])
        chunks: list[str] = []
        for item in data.get("output", []):
            for content in item.get("content", []):
                if content.get("type") in {"output_text", "text"}:
                    chunks.append(content.get("text", ""))
        return "\n".join(chunks) if chunks else json.dumps(data)[:4000]
