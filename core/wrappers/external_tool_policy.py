#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class ExternalToolPolicy:
    exact_domain_only: bool = True
    require_run_approval: bool = True
    default_timeout_seconds: int = 240
    default_rate_limit_per_second: int = 5
    allow_shell: bool = False
    allow_credential_collection: bool = False
    allow_target_data_modification: bool = False
    allow_destructive_actions: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_EXTERNAL_TOOL_POLICY = ExternalToolPolicy()


def exact_host_allowed(target: str, candidate: str) -> bool:
    try:
        target_host = (urlparse(target).hostname or "").lower()
        candidate_host = (urlparse(candidate).hostname or "").lower()
        return bool(target_host and candidate_host and target_host == candidate_host)
    except Exception:
        return False
