from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
import json

POLICY_PATH = Path("aegis_safe_policy.json")


@dataclass
class AegisSafePolicy:
    authorized_only: bool = True
    non_destructive: bool = True
    no_secret_values_in_reports: bool = True
    no_account_changes: bool = True
    no_data_export: bool = True
    no_stealth_or_evasion: bool = True
    max_requests_per_minute: int = 30
    allowed_active_methods: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
    notes: str = "AEGIS-SAFE mode: evidence-only review on owned or explicitly authorized targets."

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["allowed_active_methods"] = list(self.allowed_active_methods)
        return data


def load_policy(path: str | Path = POLICY_PATH) -> AegisSafePolicy:
    p = Path(path)
    if not p.exists():
        policy = AegisSafePolicy()
        p.write_text(json.dumps(policy.to_dict(), indent=2), encoding="utf-8")
        return policy
    data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    methods = tuple(data.get("allowed_active_methods", ["GET", "HEAD", "OPTIONS"]))
    return AegisSafePolicy(
        authorized_only=bool(data.get("authorized_only", True)),
        non_destructive=bool(data.get("non_destructive", True)),
        no_secret_values_in_reports=bool(data.get("no_secret_values_in_reports", True)),
        no_account_changes=bool(data.get("no_account_changes", True)),
        no_data_export=bool(data.get("no_data_export", True)),
        no_stealth_or_evasion=bool(data.get("no_stealth_or_evasion", True)),
        max_requests_per_minute=int(data.get("max_requests_per_minute", 30)),
        allowed_active_methods=methods,
        notes=str(data.get("notes", "AEGIS-SAFE mode.")),
    )
