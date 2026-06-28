from __future__ import annotations

from dataclasses import dataclass

try:
    from rich.console import Console
    from rich.theme import Theme
except Exception:  # pragma: no cover
    Console = None
    Theme = None


@dataclass(frozen=True)
class VulnScopeTheme:
    name: str = "VulnScope Neon Pro"
    primary: str = "cyan"
    accent: str = "magenta"
    success: str = "green"
    warning: str = "yellow"
    danger: str = "red"
    muted: str = "dim"


RICH_THEME = Theme({
    "vs.title": "bold cyan",
    "vs.subtitle": "magenta",
    "vs.ok": "bold green",
    "vs.warn": "bold yellow",
    "vs.err": "bold red",
    "vs.muted": "dim white",
    "vs.panel": "cyan",
    "vs.path": "bold blue",
    "vs.cmd": "bold green",
    "vs.agent": "bold magenta",
    "vs.ai": "bold cyan",
}) if Theme else None


def get_console() -> "Console":
    if Console is None:
        raise RuntimeError("rich is required for premium CLI. Install with: pip install rich")
    return Console(theme=RICH_THEME, highlight=False)
