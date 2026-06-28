from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    attrs: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    source: str
    target: str
    type: str
    attrs: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _id(prefix: str, value: str) -> str:
    return f"{prefix}:{hashlib.sha256(value.encode()).hexdigest()[:16]}"


def _load_json(path: str) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def build_evidence_graph(paths: list[str] | None = None) -> dict[str, Any]:
    paths = paths or [
        "reports/output/recon/domain-expansion.json",
        "reports/output/imports/har-import.json",
        "reports/output/imports/burp-import.json",
        "reports/output/agent_core/agent-core-summary.json",
        "reports/output/finding-quality.json",
    ]
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    def add_node(node_type: str, label: str, attrs: dict[str, Any] | None = None) -> str:
        nid = _id(node_type, label)
        nodes.setdefault(nid, GraphNode(nid, node_type, label, attrs or {}))
        return nid

    def add_edge(src: str, dst: str, edge_type: str, attrs: dict[str, Any] | None = None) -> None:
        edges.append(GraphEdge(src, dst, edge_type, attrs or {}))

    for path in paths:
        data = _load_json(path)
        if not data:
            continue
        artifact_id = add_node("artifact", path, {"path": path})
        if isinstance(data, dict):
            for endpoint in data.get("endpoints", []) if isinstance(data.get("endpoints"), list) else []:
                if not isinstance(endpoint, dict):
                    continue
                url = endpoint.get("url", "")
                if not url:
                    continue
                parsed = urlparse(url)
                host_id = add_node("host", parsed.netloc, {"host": parsed.netloc})
                ep_id = add_node("endpoint", url, {"method": endpoint.get("method"), "status": endpoint.get("status"), "risk_signals": endpoint.get("risk_signals", [])})
                add_edge(artifact_id, ep_id, "contains")
                add_edge(host_id, ep_id, "serves")
                for key in endpoint.get("query_keys", []) if isinstance(endpoint.get("query_keys"), list) else []:
                    param_id = add_node("parameter", f"{url}?{key}", {"key": key})
                    add_edge(ep_id, param_id, "has_parameter")
                for signal in endpoint.get("risk_signals", []) if isinstance(endpoint.get("risk_signals"), list) else []:
                    sig_id = add_node("signal", signal, {})
                    add_edge(ep_id, sig_id, "has_signal")
            for key in ["high_value_urls", "archived_urls", "urls"]:
                urls = data.get(key)
                if isinstance(urls, list):
                    for item in urls[:1000]:
                        url = item.get("url") if isinstance(item, dict) else str(item)
                        parsed = urlparse(url)
                        if not parsed.netloc:
                            continue
                        host_id = add_node("host", parsed.netloc, {"host": parsed.netloc})
                        ep_id = add_node("endpoint", f"{parsed.scheme}://{parsed.netloc}{parsed.path}", {"source_key": key})
                        add_edge(artifact_id, ep_id, "contains")
                        add_edge(host_id, ep_id, "serves")
            for key in ["accepted", "needs_review", "findings", "candidates"]:
                items = data.get(key)
                if isinstance(items, list):
                    for item in items[:500]:
                        if not isinstance(item, dict):
                            continue
                        label = item.get("title") or item.get("type") or item.get("category") or json.dumps(item, sort_keys=True)[:80]
                        f_id = add_node("finding_candidate", str(label), {"quality_score": item.get("quality_score"), "status": item.get("status"), "category": item.get("category") or item.get("type")})
                        add_edge(artifact_id, f_id, "contains")
                        url = item.get("url") or item.get("endpoint")
                        if url:
                            ep_id = add_node("endpoint", str(url), {})
                            add_edge(f_id, ep_id, "affects")
            for result in data.get("agent_results", []) if isinstance(data.get("agent_results"), list) else []:
                if not isinstance(result, dict):
                    continue
                agent_id = add_node("agent", str(result.get("agent", "agent")), {"confidence": result.get("confidence")})
                add_edge(artifact_id, agent_id, "reported_by")
                for c in result.get("candidates", []) if isinstance(result.get("candidates"), list) else []:
                    if not isinstance(c, dict):
                        continue
                    label = c.get("type") or c.get("title") or json.dumps(c, sort_keys=True)[:80]
                    cand_id = add_node("finding_candidate", str(label), c)
                    add_edge(agent_id, cand_id, "produced")
                    if c.get("url"):
                        ep_id = add_node("endpoint", str(c.get("url")), {})
                        add_edge(cand_id, ep_id, "affects")
    return {"nodes": [n.to_dict() for n in nodes.values()], "edges": [e.to_dict() for e in edges], "summary": {"nodes": len(nodes), "edges": len(edges)}}


def save_evidence_graph(out_path: str | Path = "reports/output/evidence-graph/evidence-graph.json") -> Path:
    graph = build_evidence_graph()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    md = out.with_suffix(".md")
    md.write_text(graph_to_markdown(graph), encoding="utf-8")
    return out


def graph_to_markdown(graph: dict[str, Any]) -> str:
    lines = ["# VulnScope Evidence Graph", "", f"Nodes: `{graph.get('summary', {}).get('nodes', 0)}`", f"Edges: `{graph.get('summary', {}).get('edges', 0)}`", "", "## Node Types"]
    counts: dict[str, int] = {}
    for node in graph.get("nodes", []):
        counts[node.get("type", "unknown")] = counts.get(node.get("type", "unknown"), 0) + 1
    for k, v in sorted(counts.items()):
        lines.append(f"- `{k}`: {v}")
    return "\n".join(lines)
