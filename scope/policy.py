from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    target: str
    matched_rule: str | None = None


@dataclass
class ScopePolicy:
    name: str
    allowed_hosts: list[str]
    blocked_hosts: list[str]
    allowed_schemes: list[str]
    max_requests_per_minute: int = 30
    active_testing_allowed: bool = False
    authenticated_testing_allowed: bool = False
    notes: str = ""

    @staticmethod
    def default() -> "ScopePolicy":
        return ScopePolicy(
            name="default-safe-policy",
            allowed_hosts=[],
            blocked_hosts=[],
            allowed_schemes=["http", "https"],
            max_requests_per_minute=30,
            active_testing_allowed=False,
            authenticated_testing_allowed=False,
            notes="Edit scope_policy.yaml before scanning real assets.",
        )

    def check(self, target: str) -> ScopeDecision:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = (parsed.hostname or target).lower()
        scheme = parsed.scheme.lower()
        if scheme not in self.allowed_schemes:
            return ScopeDecision(False, f"scheme not allowed: {scheme}", target, "allowed_schemes")
        for blocked in self.blocked_hosts:
            if _host_matches(host, blocked):
                return ScopeDecision(False, f"host blocked by policy: {blocked}", target, blocked)
        if not self.allowed_hosts:
            return ScopeDecision(False, "no allowed_hosts configured", target, "allowed_hosts")
        for allowed in self.allowed_hosts:
            if _host_matches(host, allowed):
                return ScopeDecision(True, f"host allowed by policy: {allowed}", target, allowed)
        return ScopeDecision(False, "host is not in allowed_hosts", target, None)

    def to_dict(self) -> dict:
        return asdict(self)


def _host_matches(host: str, pattern: str) -> bool:
    p = pattern.lower().strip()
    if p.startswith("*."):
        root = p[2:]
        return host == root or host.endswith(f".{root}")
    return host == p


def load_scope_policy(path: str | Path = "scope_policy.yaml") -> ScopePolicy:
    p = Path(path)
    if not p.exists():
        return ScopePolicy.default()
    text = p.read_text(encoding="utf-8", errors="ignore")
    data = None
    if yaml:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    data = data or {}
    return ScopePolicy(
        name=data.get("name", "custom-policy"),
        allowed_hosts=list(data.get("allowed_hosts", [])),
        blocked_hosts=list(data.get("blocked_hosts", [])),
        allowed_schemes=list(data.get("allowed_schemes", ["http", "https"])),
        max_requests_per_minute=int(data.get("max_requests_per_minute", 30)),
        active_testing_allowed=bool(data.get("active_testing_allowed", False)),
        authenticated_testing_allowed=bool(data.get("authenticated_testing_allowed", False)),
        notes=str(data.get("notes", "")),
    )


def write_default_scope_policy(path: str | Path = "scope_policy.yaml") -> Path:
    p = Path(path)
    if p.exists():
        return p
    content = """name: my-authorized-scope
allowed_hosts:
  - example.com
  - '*.example.com'
blocked_hosts:
  - admin.example.com
allowed_schemes:
  - https
max_requests_per_minute: 30
active_testing_allowed: false
authenticated_testing_allowed: false
notes: 'Only add assets you own or have explicit permission to test.'
"""
    p.write_text(content, encoding="utf-8")
    return p
