from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

OUT = Path("reports/output/artemis/knowledge")
GRAPH = OUT / "knowledge-graph.json"


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:20]


def load_graph() -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    if not GRAPH.exists():
        return {"targets": {}, "patterns": {}, "events": []}
    try:
        return json.loads(GRAPH.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {"targets": {}, "patterns": {}, "events": []}


def save_graph(graph: dict[str, Any]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    GRAPH.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")


def update_knowledge(target: str, intel: dict[str, Any], predictions: dict[str, Any]) -> dict[str, Any]:
    graph = load_graph()
    t = graph.setdefault("targets", {}).setdefault(target, {"runs": 0, "hosts": [], "urls": [], "predictions": []})
    t["runs"] = int(t.get("runs", 0)) + 1
    t["last_seen"] = time.time()
    t["hosts"] = sorted(set(t.get("hosts", [])) | set(intel.get("hosts", [])))
    t["urls"] = sorted(set(t.get("urls", [])) | set(intel.get("wayback_urls", [])))[:5000]
    pred_rows = predictions.get("predictions", []) if isinstance(predictions, dict) else []
    for p in pred_rows:
        key = fingerprint(str(p.get("type")) + str(p.get("where")))
        graph.setdefault("patterns", {})[key] = {
            "type": p.get("type"),
            "where": p.get("where"),
            "confidence": p.get("confidence"),
            "last_seen": time.time(),
            "target": target,
        }
    t["predictions"] = sorted({fingerprint(str(p.get("type")) + str(p.get("where"))) for p in pred_rows})
    graph.setdefault("events", []).append({"ts": time.time(), "target": target, "type": "artemis_cycle", "hosts": len(intel.get("hosts", [])), "predictions": len(pred_rows)})
    graph["events"] = graph["events"][-500:]
    save_graph(graph)
    return graph


def strategy_weights() -> dict[str, float]:
    graph = load_graph()
    patterns = graph.get("patterns", {})
    weights = {"passive_recon": 1.0, "public_search": 1.0, "api_prediction": 1.0, "idor_prediction": 1.0, "xss_prediction": 1.0}
    for p in patterns.values():
        ptype = str(p.get("type", "")).lower()
        conf = float(p.get("confidence") or 0)
        if "idor" in ptype:
            weights["idor_prediction"] += conf / 10
        if "xss" in ptype:
            weights["xss_prediction"] += conf / 10
        if "api" in ptype:
            weights["api_prediction"] += conf / 10
        if "public" in ptype:
            weights["public_search"] += conf / 10
    return {k: round(v, 3) for k, v in weights.items()}
