from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cli_ui.theme import get_console

try:
    from rich import box
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.prompt import Confirm, Prompt
    from rich.syntax import Syntax
except Exception:  # pragma: no cover
    box = None


def panel(title: str, body: str, style: str = "vs.panel") -> None:
    console = get_console()
    console.print(Panel(body, title=title, border_style=style, box=box.ROUNDED if box else None))


def success(msg: str) -> None:
    get_console().print(f"[vs.ok]✓[/vs.ok] {msg}")


def warn(msg: str) -> None:
    get_console().print(f"[vs.warn]⚠[/vs.warn] {msg}")


def error(msg: str) -> None:
    get_console().print(f"[vs.err]✖[/vs.err] {msg}")


def info(msg: str) -> None:
    get_console().print(f"[vs.ai]›[/vs.ai] {msg}")


def command_hint(command: str) -> None:
    get_console().print(Panel(f"[vs.cmd]{command}[/vs.cmd]", title="Command", border_style="green", box=box.ROUNDED if box else None))


def artifact_table(paths: list[str]) -> None:
    table = Table(title="Generated Artifacts", box=box.SIMPLE_HEAVY if box else None)
    table.add_column("Artifact", style="vs.path")
    table.add_column("Status")
    table.add_column("Size")
    for item in paths:
        p = Path(item)
        status = "[vs.ok]ready[/vs.ok]" if p.exists() else "[vs.warn]missing[/vs.warn]"
        size = f"{p.stat().st_size} bytes" if p.exists() else "-"
        table.add_row(item, status, size)
    get_console().print(table)


def provider_table(report: dict[str, Any]) -> None:
    table = Table(title="AI Provider Status", box=box.SIMPLE_HEAVY if box else None)
    table.add_column("Provider")
    table.add_column("Status")
    available = report.get("available", {})
    for name, ok in available.items():
        table.add_row(name, "[vs.ok]configured[/vs.ok]" if ok else "[vs.warn]missing[/vs.warn]")
    get_console().print(table)


def json_panel(title: str, data: Any) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False)
    syntax = Syntax(text, "json", theme="monokai", line_numbers=False) if 'Syntax' in globals() else text
    get_console().print(Panel(syntax, title=title, border_style="cyan", box=box.ROUNDED if box else None))


def make_progress() -> "Progress":
    return Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn())


def confirm_scope(target: str, auto_yes: bool = False) -> bool:
    if auto_yes:
        return True
    return Confirm.ask(f"Confirm [bold]{target}[/bold] is owned or explicitly authorized?", default=False)


def ask_text(label: str, default: str | None = None) -> str:
    return Prompt.ask(label, default=default) if default is not None else Prompt.ask(label)
