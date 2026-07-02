#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Any

import requests

OLLAMA_URL = os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:3b")
OLLAMA_TIMEOUT = int(os.getenv("VULNSCOPE_OLLAMA_TIMEOUT", "18"))

ALLOWED_ACTIONS = {
    "dependency_status",
    "target_profile",
    "passive_recon",
    "input_inventory",
    "hypothesis_matrix",
    "evidence_review",
    "evidence_scoring",
    "prioritize",
    "report",
    "learning",
    "adaptive_risk",
    "business_review",
    "feedback",
    "stop",
}

SCAN_ACTIONS = {"crawl", "test_parameter", "review_results", "write_report", "stop"}
SAFE_TESTS = {"reflection_canary", "classification_review", "passive_only"}

SYSTEM_PROMPT = """
You are VulnScope AI, a safe planning assistant for authorized defensive assessments.
Select only allowlisted actions. Do not request exploit payloads, credential attacks,
internal-network probing, destructive methods, brute force, or production data modification.
Return compact JSON only.
""".strip()

BATCH_PROMPT = """
Return JSON only with this schema:
{
  "public_reasoning": ["brief safe rationale 1", "brief safe rationale 2"],
  "actions": [
    {"action":"test_parameter", "test":"reflection_canary", "url":"...", "parameter":"...", "reason":"..."}
  ]
}
Rules:
- choose at most 5 actions
- choose only: crawl, test_parameter, review_results, write_report, stop
- choose only safe tests: reflection_canary, classification_review, passive_only
- use rule-based priorities first; do not overthink obvious safe GET parameters
- never include exploit strings or harmful payloads
""".strip()


@dataclass
class BrainDecision:
    analysis: str
    risk: str
    next_action: str
    action: str
    confidence: str
    reason_to_continue: str
    source: str = "deterministic-fallback"
    raw: str = ""

    def safe(self) -> dict[str, Any]:
        data = asdict(self)
        if data["action"] not in ALLOWED_ACTIONS:
            data["action"] = "stop"
            data["next_action"] = "Stop because requested action is outside safe actuator allowlist."
        return data


def _compact(value: Any, limit: int = 6000) -> str:
    text = json.dumps(value, ensure_ascii=False, default=str) if not isinstance(value, str) else value
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _extract_json(raw: str) -> dict[str, Any]:
    raw = (raw or "").strip()
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        pass
    match = re.search(r"\{.*\}", raw, re.S)
    if match:
        try:
            parsed = json.loads(match.group(0))
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _deterministic_decision(scan_output: str, context: dict[str, Any]) -> BrainDecision:
    completed = set(context.get("completed", []))
    pending = [x for x in context.get("plan", []) if x not in completed]
    action = pending[0] if pending else "stop"
    summary = _compact(scan_output, 900)
    risk = "INFO"
    if any(word in summary.lower() for word in ["confirmed", "high confidence", "sensitive", "token", "credential"]):
        risk = "HIGH"
    elif any(word in summary.lower() for word in ["review lead", "medium", "evidence"]):
        risk = "MEDIUM"
    return BrainDecision(
        analysis=f"Latest output reviewed. Next pending safe actuator is {action}.",
        risk=risk,
        next_action=f"Run safe actuator: {action}",
        action=action,
        confidence="medium" if action != "stop" else "high",
        reason_to_continue="pending actuator exists" if action != "stop" else "all actuators completed",
    )


def think(scan_output: str, context: dict[str, Any]) -> dict[str, Any]:
    """Backwards-compatible safe actuator planner."""
    prompt = {
        "target": context.get("target", "unknown"),
        "phase": context.get("phase", "agentic"),
        "completed": context.get("completed", []),
        "plan": context.get("plan", []),
        "turn": context.get("turn", 0),
        "latest_output": _compact(scan_output),
    }
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": SYSTEM_PROMPT + "\n\nINPUT:\n" + json.dumps(prompt, indent=2, ensure_ascii=False), "stream": False, "options": {"temperature": 0.1}},
            timeout=OLLAMA_TIMEOUT,
        )
        if response.status_code != 200:
            data = _deterministic_decision(scan_output, context).safe()
            data["source"] = "fallback-http-status"
            data["ollama_status"] = response.status_code
            return data
        raw = str(response.json().get("response", ""))
        parsed = _extract_json(raw)
        action = str(parsed.get("action") or parsed.get("next_action") or "stop").strip()
        if action not in ALLOWED_ACTIONS:
            action = "stop"
        return BrainDecision(
            analysis=str(parsed.get("analysis") or "Ollama returned a safe decision."),
            risk=str(parsed.get("risk") or "INFO").upper(),
            next_action=str(parsed.get("next_action") or f"Run safe actuator: {action}"),
            action=action,
            confidence=str(parsed.get("confidence") or "medium"),
            reason_to_continue=str(parsed.get("reason_to_continue") or "continue while safe pending work remains"),
            source="ollama",
            raw=raw[:1200],
        ).safe()
    except Exception as exc:
        data = _deterministic_decision(scan_output, context).safe()
        data["source"] = "deterministic-fallback"
        data["error"] = str(exc)[:500]
        return data


def deterministic_batch_actions(surface: dict[str, Any], parameters: list[dict[str, Any]], *, already_tested: set[str] | None = None, limit: int = 5) -> dict[str, Any]:
    already_tested = already_tested or set()
    actions: list[dict[str, Any]] = []
    safe = [p for p in parameters if p.get("safe_to_test") and p.get("method", "GET").upper() == "GET" and p.get("location") == "query"]
    priority = {"search-like": 100, "route-like": 85, "object-like": 75, "state-like": 60, "generic": 40}
    safe.sort(key=lambda p: priority.get(str(p.get("kind") or "generic"), 20), reverse=True)
    for param in safe:
        key = f"{param.get('url')}::{param.get('parameter')}::reflection_canary"
        if key in already_tested:
            continue
        actions.append({
            "action": "test_parameter",
            "test": "reflection_canary",
            "url": param.get("url"),
            "parameter": param.get("parameter"),
            "reason": f"safe GET query parameter classified as {param.get('kind', 'generic')}",
        })
        if len(actions) >= limit:
            break
    if not actions:
        if int(surface.get("urls_total", 0)) < int(surface.get("max_pages", 300)) and int(surface.get("urls_total", 0)) < 50:
            actions.append({"action": "crawl", "test": "passive_only", "url": surface.get("target"), "parameter": "", "reason": "surface still small; continue crawling"})
        else:
            actions.append({"action": "write_report", "test": "passive_only", "url": surface.get("target"), "parameter": "", "reason": "no untested safe GET parameters remain"})
    return {"source": "deterministic", "public_reasoning": ["Rule-based prioritization used for speed.", f"Queued {len(actions)} safe actions."], "actions": actions[:limit]}


def batch_next_actions(surface: dict[str, Any], parameters: list[dict[str, Any]], *, already_tested: set[str] | None = None, ambiguous: bool = False, no_findings_after_50: bool = False, limit: int = 5) -> dict[str, Any]:
    """Ask Ollama for a small batch only when useful; otherwise use deterministic rules.

    The returned public_reasoning is a concise rationale suitable for terminal display.
    It is not private chain-of-thought.
    """
    fallback = deterministic_batch_actions(surface, parameters, already_tested=already_tested, limit=limit)
    if not ambiguous and not no_findings_after_50:
        return fallback
    payload = {
        "surface": surface,
        "parameters": parameters[:80],
        "already_tested_count": len(already_tested or set()),
        "fallback_actions": fallback["actions"],
    }
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": SYSTEM_PROMPT + "\n" + BATCH_PROMPT + "\nINPUT:\n" + json.dumps(payload, ensure_ascii=False), "stream": False, "options": {"temperature": 0.1}},
            timeout=OLLAMA_TIMEOUT,
        )
        if response.status_code != 200:
            fallback["ollama_error"] = f"HTTP {response.status_code}"
            return fallback
        parsed = _extract_json(str(response.json().get("response", "")))
        actions = []
        for item in parsed.get("actions", []) if isinstance(parsed.get("actions"), list) else []:
            action = str(item.get("action") or "").strip()
            test = str(item.get("test") or "passive_only").strip()
            if action in SCAN_ACTIONS and test in SAFE_TESTS:
                actions.append({"action": action, "test": test, "url": item.get("url") or surface.get("target"), "parameter": item.get("parameter") or "", "reason": str(item.get("reason") or "safe batch decision")[:240]})
            if len(actions) >= limit:
                break
        if not actions:
            return fallback
        reasoning = parsed.get("public_reasoning") if isinstance(parsed.get("public_reasoning"), list) else ["Ollama returned a safe batch decision."]
        return {"source": "ollama", "public_reasoning": [str(x)[:240] for x in reasoning[:5]], "actions": actions}
    except Exception as exc:
        fallback["ollama_error"] = str(exc)[:500]
        return fallback


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="VulnScope safe Ollama brain")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scan-output", default="")
    args = parser.parse_args()
    context = {"target": args.target, "phase": "manual", "plan": sorted(ALLOWED_ACTIONS - {"stop"}), "completed": [], "turn": 1}
    print(json.dumps(think(args.scan_output, context), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
