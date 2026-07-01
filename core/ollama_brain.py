#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, asdict
from typing import Any

import requests

OLLAMA_URL = os.getenv("VULNSCOPE_OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("VULNSCOPE_OLLAMA_MODEL", "qwen2.5:14b")

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

SYSTEM_PROMPT = """
You are VulnScope AI, a zero-impact security review planner for authorized targets only.
You receive structured scan output and must choose the next safe actuator.
Never output shell commands. Never request write methods or destructive behavior.
Choose exactly one action from this allowlist:
dependency_status, target_profile, passive_recon, input_inventory, hypothesis_matrix,
evidence_review, evidence_scoring, prioritize, report, learning, adaptive_risk,
business_review, feedback, stop.

Return only JSON with these keys:
analysis, risk, next_action, action, confidence, reason_to_continue.
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
            data["next_action"] = "Stop because the requested action is outside the safe actuator allowlist."
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
    """Ask Ollama for the next safe actuator decision; fall back to deterministic planning."""
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
            json={
                "model": OLLAMA_MODEL,
                "prompt": SYSTEM_PROMPT + "\n\nINPUT:\n" + json.dumps(prompt, indent=2, ensure_ascii=False),
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=int(os.getenv("VULNSCOPE_OLLAMA_TIMEOUT", "60")),
        )
        if response.status_code != 200:
            decision = _deterministic_decision(scan_output, context)
            data = decision.safe()
            data["source"] = "fallback-http-status"
            data["ollama_status"] = response.status_code
            return data
        raw = str(response.json().get("response", ""))
        parsed = _extract_json(raw)
        action = str(parsed.get("action") or parsed.get("next_action") or "stop").strip()
        if action not in ALLOWED_ACTIONS:
            action = "stop"
        decision = BrainDecision(
            analysis=str(parsed.get("analysis") or "Ollama returned a safe decision."),
            risk=str(parsed.get("risk") or "INFO").upper(),
            next_action=str(parsed.get("next_action") or f"Run safe actuator: {action}"),
            action=action,
            confidence=str(parsed.get("confidence") or "medium"),
            reason_to_continue=str(parsed.get("reason_to_continue") or "continue while safe pending work remains"),
            source="ollama",
            raw=raw[:1200],
        )
        return decision.safe()
    except Exception as exc:
        decision = _deterministic_decision(scan_output, context)
        data = decision.safe()
        data["source"] = "deterministic-fallback"
        data["error"] = str(exc)[:500]
        return data


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
