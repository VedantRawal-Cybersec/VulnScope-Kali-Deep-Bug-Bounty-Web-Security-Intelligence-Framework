from __future__ import annotations

from cli_ui.components import ask_text, command_hint, info, panel
from cli_ui.theme import get_console

MENU = [
    ("1", "Safe Autopilot", "Run policy-controlled autonomous workflow"),
    ("2", "Full Hunt", "Run hunt.py with agents, council, quality, report v2"),
    ("3", "Import Traffic", "Import HAR or proxy XML and build evidence graph"),
    ("4", "Evidence Graph", "Build graph from current artifacts"),
    ("5", "Replay Validation", "Run safe replay validation on imported endpoints"),
    ("6", "Dashboard", "Open live terminal dashboard"),
    ("7", "Provider Status", "Show AI provider configuration"),
    ("8", "Initialize Policies", "Create scope and autonomy policy files"),
    ("0", "Exit", "Leave launcher"),
]


def show_menu() -> str:
    console = get_console()
    body = ""
    for key, title, desc in MENU:
        body += f"[bold cyan]{key}[/bold cyan]  [bold]{title}[/bold]\n    [dim]{desc}[/dim]\n"
    panel("VulnScope Command Center", body)
    return ask_text("Select option", "1")


def build_command(choice: str) -> str | None:
    if choice == "1":
        target = ask_text("Target URL/domain")
        provider = ask_text("Provider", "anthropic")
        mode = ask_text("Mode", "comprehensive")
        return f"python3 autopilot_cli.py --target {target} --mode {mode} --provider {provider} --yes"
    if choice == "2":
        target = ask_text("Target URL/domain")
        provider = ask_text("Provider", "anthropic")
        mode = ask_text("Mode", "comprehensive")
        return f"python3 hunt.py --target {target} --mode {mode} --agent-core --model-council --quality --report-v2 --provider {provider} --yes"
    if choice == "3":
        kind = ask_text("Import type: har/proxy", "har").lower()
        path = ask_text("File path")
        if kind == "proxy":
            return f"python3 traffic_bridge_cli.py --proxy-xml {path} --graph"
        return f"python3 traffic_bridge_cli.py --har {path} --graph"
    if choice == "4":
        return "python3 evidence_graph_cli.py"
    if choice == "5":
        return "python3 replay_validate_cli.py --dry-run && python3 replay_validate_cli.py --max-requests 25"
    if choice == "6":
        return "python3 dashboard_cli.py"
    if choice == "7":
        return "python3 ai_provider_cli.py --status"
    if choice == "8":
        return "python3 hunt.py --init-scope-policy && python3 autopilot_cli.py --init-policy"
    if choice == "0":
        info("Goodbye.")
        return None
    return None


def show_command_for_choice(choice: str) -> str | None:
    cmd = build_command(choice)
    if cmd:
        command_hint(cmd)
    return cmd
