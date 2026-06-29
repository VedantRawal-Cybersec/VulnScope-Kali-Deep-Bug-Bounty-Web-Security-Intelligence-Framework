from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from scope.policy import load_scope_policy
from artemis.config import ArtemisConfig, load_config
from artemis.knowledge import update_knowledge, strategy_weights
from artemis.passive_recon import run_passive_recon
from artemis.predictor import predict_from_intel
from artemis.reporter import generate_report

OUT = Path("reports/output/artemis/run")


class ArtemisBrain:
    """Passive autonomous brain.

    This brain never exploits and never changes remote state. It autonomously cycles
    through passive recon, prediction, knowledge update, and reporting for explicitly
    scoped targets only.
    """

    def __init__(self, config: ArtemisConfig | None = None, scope_policy: str = "scope_policy.yaml") -> None:
        self.config = config or load_config()
        self.scope_policy = scope_policy
        OUT.mkdir(parents=True, exist_ok=True)

    def scoped_targets(self) -> list[str]:
        scoped = []
        policy = load_scope_policy(self.scope_policy)
        for target in self.config.targets:
            decision = policy.check(target)
            if decision.allowed:
                scoped.append(target)
        return scoped

    def decide_next_action(self, target: str, previous: dict[str, Any] | None = None) -> dict[str, Any]:
        weights = strategy_weights()
        if not previous:
            return {"action": "PASSIVE_RECON", "reason": "No previous ARTEMIS cycle for this target."}
        summary = previous.get("report", {}).get("summary", {})
        if int(summary.get("predictions", 0)) < 3:
            return {"action": "BROADEN_PASSIVE_SOURCES", "reason": "Low prediction count; expand public evidence collection."}
        if float(summary.get("risk_score", 0)) >= 70:
            return {"action": "GENERATE_PRIORITY_REPORT", "reason": "High risk score; prioritize report and manual validation."}
        strongest = max(weights, key=weights.get) if weights else "passive_recon"
        return {"action": "CONTINUE_PASSIVE_LEARNING", "reason": f"Continue with strongest learned signal: {strongest}."}

    def run_once(self) -> dict[str, Any]:
        started = time.time()
        results = []
        for target in self.scoped_targets():
            target_start = time.time()
            action = self.decide_next_action(target)
            intel = run_passive_recon(target, google_limit=self.config.google_search_limit, max_public_records=self.config.max_public_records)
            predictions = predict_from_intel(intel)
            graph = update_knowledge(target, intel, predictions)
            report = generate_report(target, intel, predictions)
            results.append({
                "target": target,
                "seconds": round(time.time() - target_start, 2),
                "decision": action,
                "intel_summary": intel.get("summary", {}),
                "prediction_summary": predictions.get("summary", {}),
                "report": report.get("summary", {}),
                "knowledge_targets": len(graph.get("targets", {})),
            })
        payload = {
            "started_at": started,
            "ended_at": time.time(),
            "seconds": round(time.time() - started, 2),
            "scope_policy": self.scope_policy,
            "targets": results,
            "strategy_weights": strategy_weights(),
        }
        (OUT / "artemis-run.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        self.write_summary(payload)
        return payload

    def run_forever(self) -> None:
        while True:
            self.run_once()
            time.sleep(max(60, self.config.interval_minutes * 60))

    def write_summary(self, payload: dict[str, Any]) -> None:
        lines = ["# ARTEMIS Autonomous Run", "", f"Scope policy: `{payload['scope_policy']}`", f"Seconds: `{payload['seconds']}`", "", "## Targets"]
        for row in payload.get("targets", []):
            lines += [
                f"### {row['target']}",
                f"- Decision: `{row['decision']['action']}` — {row['decision']['reason']}",
                f"- Hosts: `{row['intel_summary'].get('hosts', 0)}`",
                f"- URLs: `{row['intel_summary'].get('wayback_urls', 0)}`",
                f"- Predictions: `{row['prediction_summary'].get('predictions', 0)}`",
                f"- Risk: `{row['report'].get('risk', 'INFO')}` score=`{row['report'].get('risk_score', 0)}`",
                "",
            ]
        lines += ["## Learned Strategy Weights"]
        for k, v in payload.get("strategy_weights", {}).items():
            lines.append(f"- `{k}`: `{v}`")
        (OUT / "artemis-run.md").write_text("\n".join(lines), encoding="utf-8")
