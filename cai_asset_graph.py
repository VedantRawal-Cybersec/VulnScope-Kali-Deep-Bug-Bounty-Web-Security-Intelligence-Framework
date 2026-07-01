#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


def node_id(kind: str, value: str) -> str:
    return hashlib.sha256(f"{kind}:{value}".encode("utf-8", errors="ignore")).hexdigest()[:16]


def _add_node(nodes: dict[str, dict[str, Any]], kind: str, value: str, **extra: Any) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    nid = node_id(kind, value.lower())
    current = nodes.setdefault(nid, {"id": nid, "kind": kind, "value": value, "first_seen": time.time()})
    current.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    return nid


def _add_edge(edges: list[dict[str, Any]], source: str, target: str, relation: str, **extra: Any) -> None:
    if not source or not target:
        return
    row = {"source": source, "target": target, "relation": relation}
    row.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    if row not in edges:
        edges.append(row)


def build_asset_graph(target: str, profile: dict[str, Any], recon: dict[str, Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    root_host = str(profile.get("host") or recon.get("host") or target)
    root_id = _add_node(nodes, "domain", root_host, role="root_target")

    for ip in profile.get("dns", {}).get("ip_addresses", []) or []:
        ip_id = _add_node(nodes, "ip", str(ip), source="dns")
        _add_edge(edges, root_id, ip_id, "resolves_to")

    for ns in profile.get("whois", {}).get("name_servers", []) or []:
        ns_id = _add_node(nodes, "nameserver", str(ns), source="whois")
        _add_edge(edges, root_id, ns_id, "uses_nameserver")

    for sub in recon.get("subdomains", []) or []:
        sub_id = _add_node(nodes, "domain", str(sub), role="discovered_subdomain")
        _add_edge(edges, root_id, sub_id, "has_subdomain")

    for url in recon.get("historical_urls", []) or []:
        url_id = _add_node(nodes, "url", str(url), source="historical_archive")
        _add_edge(edges, root_id, url_id, "has_historical_url")

    for tech in profile.get("technologies", []) or []:
        tech_id = _add_node(nodes, "technology_hint", str(tech), source="passive_profile")
        _add_edge(edges, root_id, tech_id, "has_technology_hint")

    for source_name, status in recon.get("collector_status", {}).items():
        s_id = _add_node(nodes, "collector", source_name, status=status.get("status"), detail=status.get("detail"))
        _add_edge(edges, root_id, s_id, "observed_by_collector")

    graph = {
        "target": target,
        "host": root_host,
        "generated_at": time.time(),
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "domains": len([n for n in nodes.values() if n.get("kind") == "domain"]),
            "ips": len([n for n in nodes.values() if n.get("kind") == "ip"]),
            "urls": len([n for n in nodes.values() if n.get("kind") == "url"]),
            "technology_hints": len([n for n in nodes.values() if n.get("kind") == "technology_hint"]),
        },
        "nodes": list(nodes.values()),
        "edges": edges,
    }
    return graph


def write_asset_graph(out_dir: Path, graph: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "asset-graph.json").write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# CAI Superior Asset Graph",
        "",
        f"Target: `{graph.get('target')}`",
        f"Host: `{graph.get('host')}`",
        f"Nodes: `{graph.get('summary', {}).get('nodes', 0)}`",
        f"Edges: `{graph.get('summary', {}).get('edges', 0)}`",
        f"Domains: `{graph.get('summary', {}).get('domains', 0)}`",
        f"IPs: `{graph.get('summary', {}).get('ips', 0)}`",
        f"URLs: `{graph.get('summary', {}).get('urls', 0)}`",
        f"Technology hints: `{graph.get('summary', {}).get('technology_hints', 0)}`",
        "",
        "## Nodes",
    ]
    for node in graph.get("nodes", [])[:300]:
        lines.append(f"- `{node.get('kind')}` `{node.get('value')}` id=`{node.get('id')}`")
    lines += ["", "## Edges"]
    for edge in graph.get("edges", [])[:300]:
        lines.append(f"- `{edge.get('source')}` --{edge.get('relation')}--> `{edge.get('target')}`")
    (out_dir / "asset-graph.md").write_text("\n".join(lines), encoding="utf-8")
