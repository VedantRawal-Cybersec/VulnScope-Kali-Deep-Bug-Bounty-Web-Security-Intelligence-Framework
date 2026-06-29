from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

DEFAULT_CONFIG = Path("artemis_config.yaml")


@dataclass
class ArtemisConfig:
    targets: list[str]
    passive_only: bool = True
    require_scope_policy: bool = True
    interval_minutes: int = 360
    report_every_cycles: int = 1
    google_search_limit: int = 5
    max_public_records: int = 500
    respect_rate_limits: bool = True
    no_secret_values_in_reports: bool = True
    notes: str = "ARTEMIS passive autonomous intelligence. Authorized targets only."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_config() -> ArtemisConfig:
    return ArtemisConfig(targets=["example.com"])


def write_default(path: str | Path = DEFAULT_CONFIG) -> Path:
    p = Path(path)
    cfg = default_config().to_dict()
    if yaml:
        p.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    else:
        p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return p


def load_config(path: str | Path = DEFAULT_CONFIG) -> ArtemisConfig:
    p = Path(path)
    if not p.exists():
        write_default(p)
    text = p.read_text(encoding="utf-8", errors="ignore")
    if p.suffix.lower() in {".yaml", ".yml"} and yaml:
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text) if text.strip() else {}
    return ArtemisConfig(
        targets=list(data.get("targets") or []),
        passive_only=bool(data.get("passive_only", True)),
        require_scope_policy=bool(data.get("require_scope_policy", True)),
        interval_minutes=int(data.get("interval_minutes", 360)),
        report_every_cycles=int(data.get("report_every_cycles", 1)),
        google_search_limit=int(data.get("google_search_limit", 5)),
        max_public_records=int(data.get("max_public_records", 500)),
        respect_rate_limits=bool(data.get("respect_rate_limits", True)),
        no_secret_values_in_reports=bool(data.get("no_secret_values_in_reports", True)),
        notes=str(data.get("notes", "ARTEMIS passive autonomous intelligence.")),
    )
