from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
import json

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


@dataclass
class AutonomyPolicy:
    level: int = 2
    max_cycles: int = 3
    max_runtime_minutes: int = 30
    allow_active_tools: bool = False
    allow_authenticated_review: bool = False
    allow_model_council: bool = True
    allow_har_import: bool = True
    allow_report_generation: bool = True
    require_scope_policy: bool = True
    stop_on_scope_block: bool = True
    min_quality_threshold: float = 0.45
    notes: str = "Safe autonomy: plan, review, dedupe, report. No destructive or unauthorized actions."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def allows_stage(self, stage: str) -> bool:
        if stage in {"scope", "passive_recon", "agent_review", "quality"}:
            return True
        if stage == "model_council":
            return self.allow_model_council and self.level >= 2
        if stage == "active_tools":
            return self.allow_active_tools and self.level >= 4
        if stage == "authenticated_review":
            return self.allow_authenticated_review and self.level >= 4
        if stage == "report":
            return self.allow_report_generation and self.level >= 1
        return False


def default_policy() -> AutonomyPolicy:
    return AutonomyPolicy()


def load_autonomy_policy(path: str | Path = "autonomy_policy.yaml") -> AutonomyPolicy:
    p = Path(path)
    if not p.exists():
        return default_policy()
    text = p.read_text(encoding="utf-8", errors="ignore")
    if yaml:
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    return AutonomyPolicy(
        level=int(data.get("level", 2)),
        max_cycles=int(data.get("max_cycles", 3)),
        max_runtime_minutes=int(data.get("max_runtime_minutes", 30)),
        allow_active_tools=bool(data.get("allow_active_tools", False)),
        allow_authenticated_review=bool(data.get("allow_authenticated_review", False)),
        allow_model_council=bool(data.get("allow_model_council", True)),
        allow_har_import=bool(data.get("allow_har_import", True)),
        allow_report_generation=bool(data.get("allow_report_generation", True)),
        require_scope_policy=bool(data.get("require_scope_policy", True)),
        stop_on_scope_block=bool(data.get("stop_on_scope_block", True)),
        min_quality_threshold=float(data.get("min_quality_threshold", 0.45)),
        notes=str(data.get("notes", "")),
    )


def write_default_autonomy_policy(path: str | Path = "autonomy_policy.yaml") -> Path:
    p = Path(path)
    if p.exists():
        return p
    p.write_text("""level: 2
max_cycles: 3
max_runtime_minutes: 30
allow_active_tools: false
allow_authenticated_review: false
allow_model_council: true
allow_har_import: true
allow_report_generation: true
require_scope_policy: true
stop_on_scope_block: true
min_quality_threshold: 0.45
notes: 'Safe autonomous mode. Increase level only for owned labs or explicitly authorized assets.'
""", encoding="utf-8")
    return p
