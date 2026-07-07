#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class LearningGraphBuilder:
    """Builds a local reasoning graph from scan artifacts and learning records."""

    def __init__(self, *, state: Any | None = None, dashboard: Any | None = None, out_dir: str | None = None) -> None:
        self.state = state
        self.dashboard = dashboard
        self.target = getattr(state, "target", "") if state is not None else ""
        self.out_dir = Path(out_dir) if out_dir else Path(getattr(state, "out_dir", "reports/output/learning-graph"))
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []

    def dash(self, action: str, status: str = "running") -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="Learning Graph", phase_progress=83, current_agent="LearningGraphAgent", current_tool="learning_graph", tool_status=status, action=action, endpoint=self.target or "local", safety_status="offline graph synthesis")

    @staticmethod
    def node_id(kind: str, value: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_.:-]+", "_", value)[:160]
        return f"{kind}:{safe}"

    def add_node(self, kind: str, value: str, **props: Any) -> str:
        nid = self.node_id(kind, value or kind)
        row = self.nodes.setdefault(nid, {"id": nid, "kind": kind, "value": value})
        row.update({k: v for k, v in props.items() if v is not None})
        return nid

    def add_edge(self, src: str, dst: str, relation: str, **props: Any) -> None:
        self.edges.append({"source": src, "target": dst, "relation": relation, **{k: v for k, v in props.items() if v is not None}})

    def from_state(self) -> None:
        if self.state is None:
            return
        target = self.add_node("target", getattr(self.state, "target", ""))
        for url in (getattr(self.state, "urls", {}) or {}).keys():
            uid = self.add_node("url", str(url), path=urlparse(str(url)).path or "/")
            self.add_edge(target, uid, "has_url")
        for param in (getattr(self.state, "params", {}) or {}).values():
            pid = self.add_node("parameter", getattr(param, "name", ""), kind=getattr(param, "kind", ""), risk_score=getattr(param, "risk_score", 0))
            uid = self.add_node("url", getattr(param, "url", ""))
            self.add_edge(uid, pid, "has_parameter")
        for finding in getattr(self.state, "findings", []) or []:
            fid = self.add_node("finding", str(finding.get("title") or finding.get("id") or "finding"), status=finding.get("status"), severity=finding.get("severity"), category=finding.get("category"))
            affected = finding.get("affected_url") or finding.get("url")
            if affected:
                uid = self.add_node("url", str(affected))
                self.add_edge(uid, fid, "has_finding")
            self.add_edge(target, fid, "reported")

    def from_artifacts(self) -> None:
        roots = [self.out_dir.parent if self.out_dir.name == "learning-graph" else self.out_dir, Path("reports/output")]
        seen: set[Path] = set()
        for root in roots:
            if not root.exists():
                continue
            for path in list(root.rglob("technology-intelligence.json"))[:20] + list(root.rglob("api-discovery.json"))[:20] + list(root.rglob("advisory-enrichment.json"))[:20]:
                if path in seen:
                    continue
                seen.add(path)
                try:
                    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    continue
                artifact = self.add_node("artifact", str(path))
                for tech in data.get("technologies", []) or []:
                    name = str(tech.get("name") or "")
                    if name:
                        tid = self.add_node("technology", name, confidence=tech.get("confidence"), source=str(path))
                        self.add_edge(artifact, tid, "mentions")
                for endpoint in data.get("endpoints", []) or []:
                    url = str(endpoint.get("url") or "")
                    if url:
                        eid = self.add_node("endpoint", url, method=endpoint.get("method"))
                        self.add_edge(artifact, eid, "contains_endpoint")
                for item in data.get("items", []) or data.get("advisories", []) or []:
                    cve = str(item.get("cve") or item.get("id") or "")
                    if cve.startswith("CVE-"):
                        cid = self.add_node("advisory", cve, known_exploited=item.get("known_exploited"))
                        self.add_edge(artifact, cid, "contains_advisory")

    def write(self) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "nodes": list(self.nodes.values()), "edges": self.edges, "counts": {"nodes": len(self.nodes), "edges": len(self.edges)}}
        json_path = self.out_dir / "learning-graph.json"
        md_path = self.out_dir / "learning-graph.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        lines = ["# Learning Graph", "", f"Target: `{self.target or 'local'}`", f"Nodes: `{len(self.nodes)}`", f"Edges: `{len(self.edges)}`", "", "## Node Types"]
        counts: dict[str, int] = {}
        for row in self.nodes.values():
            counts[row["kind"]] = counts.get(row["kind"], 0) + 1
        for kind, count in sorted(counts.items()):
            lines.append(f"- `{kind}`: `{count}`")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"learning_graph_json": str(json_path), "learning_graph_md": str(md_path)}

    def run(self) -> dict[str, Any]:
        self.dash("Building learning graph")
        self.from_state()
        self.from_artifacts()
        reports = self.write()
        self.dash("Learning graph built", status="completed")
        return {"ok": True, "nodes": len(self.nodes), "edges": len(self.edges), "reports": reports}
