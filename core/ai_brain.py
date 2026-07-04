#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

try:
    import ollama  # type: ignore
except Exception:  # pragma: no cover
    ollama = None


class AIBrain:
    """Memory-backed assistant layer for the prompt orchestrator.

    It uses Ollama when available and falls back to deterministic local memory
    when Ollama is not running. This keeps VulnScope usable on clean systems.
    """

    def __init__(self, model: str | None = None, collection_name: str = "vulnscope") -> None:
        self.model = model or os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b")
        self.collection_name = collection_name
        self.memory_path = Path("reports/output/prompt-engine/memory.jsonl")
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)

    def store_decision(self, context: str, decision: str, outcome: str) -> None:
        record = {"time": time.time(), "context": context, "decision": decision, "outcome": outcome}
        with self.memory_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def retrieve_similar_decisions(self, current_context: str, top_k: int = 5) -> list[dict[str, Any]]:
        if not self.memory_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line in self.memory_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-max(20, top_k):]:
            try:
                item = json.loads(line)
            except Exception:
                continue
            rows.append({"context": item.get("context", ""), "metadata": {"decision": item.get("decision", ""), "outcome": item.get("outcome", "")}})
        return rows[-top_k:]

    def chat(self, prompt: str) -> str:
        if ollama is None:
            return ""
        try:
            response = ollama.chat(model=self.model, messages=[{"role": "user", "content": prompt}])
            return str(response.get("message", {}).get("content", "")).strip()
        except Exception:
            return ""

    def decide_next_action(self, context: dict[str, Any], available_tools: list[str]) -> str:
        if not available_tools:
            return ""
        prompt = "Return only one item from this tool list: " + ", ".join(available_tools) + "\nContext:\n" + json.dumps(context, indent=2, ensure_ascii=False)
        answer = self.chat(prompt)
        return answer if answer in available_tools else available_tools[0]

    def analyze_findings(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return "No findings were captured. Check tool registration, scope, and dynamic-tool summary logs."
        prompt = "Summarize these findings with severity ranking and practical remediation:\n" + json.dumps(findings[:50], indent=2, ensure_ascii=False)
        answer = self.chat(prompt)
        if answer:
            return answer
        counts: dict[str, int] = {}
        for finding in findings:
            sev = str(finding.get("severity") or "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return "Findings summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))

    def generate_response(self, user_prompt: str, plan: dict[str, Any], result: dict[str, Any]) -> str:
        prompt = (
            "User request:\n" + user_prompt +
            "\n\nExecuted plan:\n" + json.dumps(plan, indent=2, ensure_ascii=False) +
            "\n\nResult summary:\n" + json.dumps(result, indent=2, ensure_ascii=False)[:8000] +
            "\n\nWrite a concise professional response with what was done, what was found, and where reports were saved."
        )
        answer = self.chat(prompt)
        if answer:
            return answer
        return result.get("summary") or "Plan completed. Review generated reports for details."
