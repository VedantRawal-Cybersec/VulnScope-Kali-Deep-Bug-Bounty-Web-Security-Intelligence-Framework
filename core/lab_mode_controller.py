#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cai_scope_guard import cai_output_dir, normalize_target


@dataclass
class LabModePolicy:
    target: str
    host: str
    enabled: bool = False
    external_tools_enabled: bool = False
    exact_host_only: bool = True
    authorization_confirmed: bool = False
    max_external_tool_seconds: int = 120
    max_urls_per_tool: int = 25
    allowed_tools: list[str] = field(default_factory=lambda: ["nuclei", "ffuf", "katana", "dalfox", "sqlmap"])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LabModeController:
    """Policy gate for lab-only enhanced validation.

    The controller enforces:
    - lab mode must be selected,
    - authorization must be confirmed,
    - external tools require an extra opt-in flag,
    - URLs must stay on the exact hostname supplied by the user.
    """

    def __init__(
        self,
        target: str,
        *,
        scan_mode: str = "passive",
        authorization_confirmed: bool = False,
        external_tools_enabled: bool = False,
        max_external_tool_seconds: int = 120,
        max_urls_per_tool: int = 25,
    ) -> None:
        normalized = normalize_target(target)
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        self.policy = LabModePolicy(
            target=normalized,
            host=host,
            enabled=scan_mode == "lab",
            external_tools_enabled=bool(external_tools_enabled and scan_mode == "lab"),
            authorization_confirmed=authorization_confirmed,
            max_external_tool_seconds=max(15, int(max_external_tool_seconds)),
            max_urls_per_tool=max(1, int(max_urls_per_tool)),
        )
        self.out_dir = cai_output_dir(normalized)

    def allowed_url(self, url: str) -> bool:
        try:
            parsed = urlparse(normalize_target(url))
            host = (parsed.hostname or "").lower()
            return bool(host and host == self.policy.host and parsed.scheme in {"http", "https"})
        except Exception:
            return False

    def require_lab(self) -> tuple[bool, str]:
        if not self.policy.enabled:
            return False, "lab mode is not enabled"
        if not self.policy.authorization_confirmed:
            return False, "authorization is not confirmed"
        return True, "lab mode authorized"

    def require_external_tools(self) -> tuple[bool, str]:
        ok, reason = self.require_lab()
        if not ok:
            return ok, reason
        if not self.policy.external_tools_enabled:
            return False, "external tools require --enable-external-tools with --lab-mode"
        return True, "external tools authorized for lab mode"

    def tool_allowed(self, tool_name: str) -> tuple[bool, str]:
        ok, reason = self.require_external_tools()
        if not ok:
            return ok, reason
        if tool_name not in self.policy.allowed_tools:
            return False, f"tool not in allowlist: {tool_name}"
        return True, "tool allowed"

    def write_policy(self) -> Path:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        path = self.out_dir / "lab-mode-policy.json"
        payload = {"generated_at": time.time(), "policy": self.policy.to_dict()}
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path
