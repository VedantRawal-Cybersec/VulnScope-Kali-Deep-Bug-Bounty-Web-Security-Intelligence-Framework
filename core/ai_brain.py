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
    """Memory-backed assistant layer for the prompt orchestrator."""

    def __init__(self, model: str = "deepseek-local", collection_name: str = "vulnscope") -> None:
        self.model = model
        self.collection_name = collection_name
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://192.168.199.1:11434").rstrip("/")
        self.client = ollama.Client(host=self.ollama_host)

        self.chroma_path = "./chroma_db"
        self.embedding_url = f"{self.ollama_host}/api/embeddings"
        self.embedding_function = embedding_functions.OllamaEmbeddingFunction(
            url=self.embedding_url,
            model_name=self.model,
        )
        self.chroma_client = chromadb.PersistentClient(path=self.chroma_path)
        self.collection = self.chroma_client.get_or_create_collection(
            name=self.collection_name,
            embedding_function=self.embedding_function,
        )

        self.memory_path = Path("reports/output/prompt-engine/memory.jsonl")
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)

    def store_decision(self, context: str, decision: str, outcome: str) -> None:
        record = {"time": time.time(), "context": context, "decision": decision, "outcome": outcome}
        with self.memory_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

        try:
            doc_id = f"decision_{int(record['time'] * 1000)}"
            self.collection.add(
                ids=[doc_id],
                documents=[context],
                metadatas=[{"decision": decision, "outcome": outcome, "time": record["time"]}],
            )
        except Exception:
            pass

    def retrieve_similar(self, current_context: str, top_k: int = 5) -> list[dict[str, Any]]:
        try:
            result = self.collection.query(
                query_texts=[current_context],
                n_results=top_k,
            )
            documents = result.get("documents", [[]])[0]
            metadatas = result.get("metadatas", [[]])[0]
            rows: list[dict[str, Any]] = []
            for document, metadata in zip(documents, metadatas):
                rows.append({"context": document, "metadata": metadata or {}})
            if rows:
                return rows
        except Exception:
            pass

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

    def retrieve_similar_decisions(self, current_context: str, top_k: int = 5) -> list[dict[str, Any]]:
        return self.retrieve_similar(current_context, top_k)

    def chat(self, prompt: str) -> str:
        try:
            response = self.client.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
            )
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
