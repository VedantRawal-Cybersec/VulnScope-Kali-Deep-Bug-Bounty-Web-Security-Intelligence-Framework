#!/usr/bin/env python3
from __future__ import annotations

import ollama
import os
import chromadb
from chromadb.utils import embedding_functions
import json
import time
from pathlib import Path
from typing import Any


class AIBrain:
    def __init__(self, model: str = "deepseek-local", collection_name: str = "vulnscope") -> None:
        self.model = model or os.getenv("VULNSCOPE_OLLAMA_MODEL", "deepseek-local")
        self.collection_name = collection_name
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://192.168.199.1:11434").rstrip("/")
        self.client = ollama.Client(host=self.ollama_host)
        self.chroma_path = "./chroma_db"
        self.embedding_url = f"{self.ollama_host}/api/embeddings"
        self.memory_path = Path("reports/output/prompt-engine/memory.jsonl")
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        self.collection = None
        try:
            self.embedding_function = embedding_functions.OllamaEmbeddingFunction(url=self.embedding_url, model_name=self.model)
            self.chroma_client = chromadb.PersistentClient(path=self.chroma_path)
            self.collection = self.chroma_client.get_or_create_collection(name=self.collection_name, embedding_function=self.embedding_function)
        except Exception:
            self.embedding_function = None
            self.chroma_client = None
            self.collection = None

    def ask_ollama(self, prompt: str, *, system: str = "", temperature: float = 0.2) -> str:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            response = self.client.chat(model=self.model, messages=messages, options={"temperature": temperature})
            return str(response.get("message", {}).get("content", "")).strip()
        except Exception:
            return ""

    def chat(self, prompt: str) -> str:
        return self.ask_ollama(prompt)

    def store_decision(self, context: str, decision: str, outcome: str, metadata: dict[str, Any] | None = None) -> None:
        record = {"time": time.time(), "context": context, "decision": decision, "outcome": outcome, "metadata": metadata or {}}
        with self.memory_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        if self.collection is not None:
            try:
                doc_id = f"decision_{int(record['time'] * 1000)}"
                meta = {"decision": decision, "outcome": outcome, "time": record["time"], **{k: str(v) for k, v in (metadata or {}).items()}}
                self.collection.add(ids=[doc_id], documents=[context], metadatas=[meta])
            except Exception:
                pass

    def retrieve_similar(self, current_context: str, top_k: int = 5) -> list[dict[str, Any]]:
        if self.collection is not None:
            try:
                result = self.collection.query(query_texts=[current_context], n_results=top_k)
                documents = result.get("documents", [[]])[0]
                metadatas = result.get("metadatas", [[]])[0]
                rows = [{"context": document, "metadata": metadata or {}} for document, metadata in zip(documents, metadatas)]
                if rows:
                    return rows
            except Exception:
                pass
        if not self.memory_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line in self.memory_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-max(50, top_k):]:
            try:
                item = json.loads(line)
            except Exception:
                continue
            rows.append({"context": item.get("context", ""), "metadata": {"decision": item.get("decision", ""), "outcome": item.get("outcome", ""), **dict(item.get("metadata") or {})}})
        return rows[-top_k:]

    def retrieve_similar_decisions(self, current_context: str, top_k: int = 5) -> list[dict[str, Any]]:
        return self.retrieve_similar(current_context, top_k)

    def _json_from_model(self, prompt: str, fallback: Any) -> Any:
        answer = self.ask_ollama(prompt)
        if not answer:
            return fallback
        for opener, closer in [("{", "}"), ("[", "]")]:
            try:
                start = answer.find(opener)
                end = answer.rfind(closer)
                if start >= 0 and end > start:
                    return json.loads(answer[start:end + 1])
            except Exception:
                continue
        return fallback

    def decide_next_action(self, context: dict[str, Any], available_tools: list[str]) -> str:
        memory = self.retrieve_similar(json.dumps(context, ensure_ascii=False), top_k=5)
        allowed = ["finish", "generate_report", "inject_endpoints", *[f"run_tool:{tool}" for tool in available_tools]]
        prompt = "Choose one next VulnScope action from the allowlist. Return JSON only: {\"action\": \"...\", \"reason\": \"...\"}.\nAllowlist:\n" + json.dumps(allowed, indent=2) + "\nContext:\n" + json.dumps(context, indent=2, ensure_ascii=False) + "\nMemory:\n" + json.dumps(memory, indent=2, ensure_ascii=False)
        result = self._json_from_model(prompt, {"action": "generate_report", "reason": "fallback"})
        action = str(result.get("action", "")).strip()
        return action if action in allowed else (f"run_tool:{available_tools[0]}" if available_tools else "generate_report")

    def generate_priority_report(self, findings: list[dict[str, Any]]) -> str:
        prompt = "Generate a concise Markdown priority report for these findings. Include impact, priority, remediation order, and review notes.\n" + json.dumps(findings[:100], indent=2, ensure_ascii=False)
        answer = self.ask_ollama(prompt)
        return answer if answer else self.analyze_findings(findings)

    def analyze_findings(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return "No findings were captured. Check tool registration, scope, and dynamic-tool summary logs."
        prompt = "Summarize these findings with severity ranking and practical remediation:\n" + json.dumps(findings[:50], indent=2, ensure_ascii=False)
        answer = self.ask_ollama(prompt)
        if answer:
            return answer
        counts: dict[str, int] = {}
        for finding in findings:
            sev = str(finding.get("severity") or "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return "Findings summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))

    def generate_response(self, user_prompt: str, plan: dict[str, Any], result: dict[str, Any]) -> str:
        prompt = "User request:\n" + user_prompt + "\n\nExecuted plan:\n" + json.dumps(plan, indent=2, ensure_ascii=False) + "\n\nResult summary:\n" + json.dumps(result, indent=2, ensure_ascii=False)[:8000] + "\n\nWrite a concise professional response."
        answer = self.ask_ollama(prompt)
        return answer if answer else result.get("summary") or "Plan completed. Review generated reports for details."
