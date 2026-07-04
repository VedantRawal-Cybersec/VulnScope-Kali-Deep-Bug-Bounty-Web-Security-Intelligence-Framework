#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


class ContextStore:
    """Small graph-backed context store for orchestration and reporting."""

    def __init__(self) -> None:
        self.subdomains: set[str] = set()
        self.endpoints: dict[str, set[str]] = {}
        self.findings: list[dict[str, Any]] = []
        self.correlated: list[dict[str, Any]] = []
        self.tool_history: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.target: str | None = None
        self.scope: str | None = None
        self.graph: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    def add_endpoint(self, url: str, parameters: list[str] | set[str] | None = None) -> None:
        self.endpoints.setdefault(url, set()).update(parameters or [])
        self.graph[url]["type"].add("endpoint")
        for parameter in parameters or []:
            self.graph[url]["parameter"].add(str(parameter))

    def add_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(finding)
        enriched["signature"] = self._signature(enriched)
        if enriched["signature"] not in {item.get("signature") for item in self.findings}:
            self.findings.append(enriched)
        url = str(enriched.get("url") or enriched.get("affected_url") or enriched.get("target") or "")
        if url:
            self.graph[url]["has_finding"].add(str(enriched.get("type") or enriched.get("title") or "external observation"))
        parameter = enriched.get("parameter")
        if url and parameter:
            self.graph[url]["parameter"].add(str(parameter))
        return enriched

    def add_tool_run(self, tool_name: str, payload: dict[str, Any]) -> None:
        self.tool_history[tool_name].append(payload)

    def _signature(self, finding: dict[str, Any]) -> str:
        data = f"{finding.get('target') or finding.get('url') or finding.get('affected_url')}|{finding.get('type') or finding.get('title')}|{finding.get('evidence')}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def get_all_urls(self) -> set[str]:
        return set(self.endpoints.keys())

    def get_tools_by_phase(self, phase: str) -> list[str]:
        try:
            from core.tool_registry import ToolRegistry
            return [tool.tool_id for tool in ToolRegistry().list(enabled_only=True, phase=phase)]
        except Exception:
            return []

    def to_dict(self) -> dict[str, Any]:
        graph = {subject: {predicate: sorted(values) for predicate, values in edges.items()} for subject, edges in self.graph.items()}
        return {
            "target": self.target,
            "scope": self.scope,
            "subdomains": sorted(self.subdomains),
            "endpoints": {url: sorted(params) for url, params in self.endpoints.items()},
            "findings": self.findings,
            "correlated": self.correlated,
            "tool_history": dict(self.tool_history),
            "graph": graph,
        }

    def save_snapshot(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
