from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from normalizers.evidence import normalize_all

OUT = Path("reports/output/asset-graph")


def build_asset_graph(target: str | None = None) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    normalized = normalize_all(target)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def node(node_id: str, kind: str, **props: Any) -> None:
        nodes.setdefault(node_id, {"id": node_id, "kind": kind, **props})

    for host in normalized.get("hosts", []):
        node(f"host:{host}", "host", host=host)
    for endpoint in normalized.get("endpoints", []):
        eid = "url:" + endpoint["url"]
        hid = "host:" + endpoint["host"]
        node(eid, "endpoint", url=endpoint["url"], path=endpoint["path"], tags=endpoint.get("risk_tags", []))
        edges.append({"from": hid, "to": eid, "type": "serves"})
        for param in endpoint.get("params", []):
            pid = "param:" + param
            node(pid, "parameter", name=param)
            edges.append({"from": eid, "to": pid, "type": "has_param"})
        for tag in endpoint.get("risk_tags", []):
            tid = "tag:" + tag
            node(tid, "risk_tag", tag=tag)
            edges.append({"from": eid, "to": tid, "type": "has_risk_tag"})
    for i, cand in enumerate(normalized.get("candidates", [])):
        cid = f"candidate:{i}"
        cat = str(cand.get("category") or cand.get("detector") or "unknown")
        node(cid, "candidate", title=cand.get("title") or cat, category=cat, source=cand.get("source_file"))
        url = cand.get("url") or cand.get("endpoint") or cand.get("target")
        if isinstance(url, str) and url:
            edges.append({"from": "url:" + url, "to": cid, "type": "supports_candidate"})
    graph = {
        "target": target or normalized.get("target"),
        "generated_at": time.time(),
        "summary": {"nodes": len(nodes), "edges": len(edges), **normalized.get("summary", {})},
        "nodes": sorted(nodes.values(), key=lambda x: x["id"]),
        "edges": edges,
    }
    (OUT / "asset-graph.json").write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# VulnScope Asset Graph — {graph['target']}", "", f"Nodes: `{len(nodes)}`", f"Edges: `{len(edges)}`", "", "## High-Signal Paths"]
    for edge in edges[:150]:
        lines.append(f"- `{edge['from']}` --{edge['type']}--> `{edge['to']}`")
    (OUT / "asset-graph.md").write_text("\n".join(lines), encoding="utf-8")
    return graph
