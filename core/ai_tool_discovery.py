#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
from typing import Any

import requests

from core.ai_brain import AIBrain


class AIToolDiscovery:
    def __init__(self, brain: AIBrain | None = None, github_token: str | None = None) -> None:
        self.brain = brain or AIBrain()
        self.github_token = github_token or os.getenv("GITHUB_TOKEN", "")
        self.session = requests.Session()
        if self.github_token:
            self.session.headers.update({"Authorization": f"Bearer {self.github_token}"})
        self.session.headers.update({"Accept": "application/vnd.github+json"})

    def generate_queries(self, context: dict[str, Any], limit: int = 5) -> list[str]:
        prompt = "Generate GitHub search queries for defensive web assessment CLI tools. Return JSON only: {\"queries\": [\"...\"]}. Context:\n" + json.dumps(context, indent=2, ensure_ascii=False)
        answer = self.brain.ask_ollama(prompt)
        queries: list[str] = []
        try:
            data = json.loads(answer[answer.find("{"):answer.rfind("}") + 1])
            queries = [str(item) for item in data.get("queries", []) if str(item).strip()]
        except Exception:
            queries = []
        fallback = [
            "web vulnerability scanner json cli",
            "http web crawler security scanner json cli",
            "parameter discovery web security cli",
            "javascript endpoint discovery security cli",
            "subdomain discovery bug bounty cli json",
        ]
        merged: list[str] = []
        for item in [*queries, *fallback]:
            if item not in merged:
                merged.append(item)
        return merged[:limit]

    def _safe_repo(self, repo: dict[str, Any]) -> bool:
        text = " ".join([str(repo.get("full_name", "")), str(repo.get("description", "")), str(repo.get("topics", ""))]).lower()
        blocked = ["ransomware", "stealer", "botnet", "keylogger", "ddos", "phishing", "credential", "persistence"]
        return not any(word in text for word in blocked)

    def search_github(self, query: str, limit: int = 5) -> list[str]:
        safe_query = re.sub(r"[^a-zA-Z0-9_./: +#-]", " ", query).strip()
        if not safe_query:
            return []
        try:
            response = self.session.get(
                "https://api.github.com/search/repositories",
                params={"q": f"{safe_query} stars:>10", "sort": "stars", "order": "desc", "per_page": min(limit, 10)},
                timeout=20,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception:
            return []
        results: list[str] = []
        for repo in payload.get("items", []):
            if not self._safe_repo(repo):
                continue
            clone_url = repo.get("clone_url") or repo.get("html_url")
            if clone_url and str(clone_url).startswith("https://github.com/"):
                results.append(str(clone_url))
        return results[:limit]

    def discover(self, context: dict[str, Any], per_query: int = 3, max_total: int = 10) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for query in self.generate_queries(context):
            for url in self.search_github(query, limit=per_query):
                if url not in seen:
                    seen.add(url)
                    urls.append(url)
                if len(urls) >= max_total:
                    return urls
        return urls
