#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import time
from pathlib import Path
from typing import Any

from top100_integrator_cli import build_inventory, write_status
from universal_tool_installer import install_missing_from_inventory

OUT = Path("reports/output/top100-tools")
DASH_JSON = OUT / "tool-setup-dashboard.json"
DASH_MD = OUT / "tool-setup-dashboard.md"
DASH_HTML = OUT / "tool-setup-dashboard.html"
INSTALL_LOG = OUT / "tool-setup-install.json"


def _bucket(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    installed = [r for r in rows if r.get("installed")]
    missing = [r for r in rows if not r.get("installed")]
    auto_missing = [r for r in missing if r.get("auto_install_supported")]
    manual_missing = [r for r in missing if not r.get("auto_install_supported")]
    safe_runners = [r for r in rows if r.get("safe_runner_available")]
    return {"installed": installed, "missing": missing, "auto_missing": auto_missing, "manual_missing": manual_missing, "safe_runners": safe_runners}


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    b = _bucket(rows)
    return {
        "total_integrated": len(rows),
        "installed": len(b["installed"]),
        "missing": len(b["missing"]),
        "auto_installable_missing": len(b["auto_missing"]),
        "manual_or_unsupported_missing": len(b["manual_missing"]),
        "safe_runners_wired": len(b["safe_runners"]),
    }


def _line() -> None:
    print("─" * 92, flush=True)


def _print_table(title: str, rows: list[dict[str, Any]], limit: int | None = None) -> None:
    print(f"\n{title} ({len(rows)})", flush=True)
    _line()
    if not rows:
        print("None", flush=True)
        return
    shown = rows[:limit] if limit else rows
    for r in shown:
        idx = int(r.get("index", 0))
        name = str(r.get("name", ""))
        binary = str(r.get("binary", ""))
        method = str(r.get("install_method") or "manual")
        installed = "YES" if r.get("installed") else "NO"
        runner = "SAFE-RUNNER" if r.get("safe_runner_available") else str(r.get("profile", ""))
        path = str(r.get("path") or "-")
        print(f"{idx:03d}  {name:<24} binary={binary:<18} installed={installed:<3} method={method:<12} mode={runner:<18} path={path}", flush=True)
    if limit and len(rows) > limit:
        print(f"... {len(rows) - limit} more shown in reports/output/top100-tools/tool-setup-dashboard.md", flush=True)


def show_dashboard(rows: list[dict[str, Any]], *, title: str = "VULNSCOPE TOOL SETUP DASHBOARD") -> None:
    s = _summary(rows)
    b = _bucket(rows)
    print("\n" + "═" * 92, flush=True)
    print(title, flush=True)
    print("This appears before URL input so the operator can verify and repair tools first.", flush=True)
    print("═" * 92, flush=True)
    print(
        f"Integrated: {s['total_integrated']} | Installed: {s['installed']} | Missing: {s['missing']} | "
        f"Auto-installable missing: {s['auto_installable_missing']} | Manual/unsupported: {s['manual_or_unsupported_missing']} | "
        f"Safe runners wired: {s['safe_runners_wired']}",
        flush=True,
    )
    _print_table("INSTALLED TOOLS", b["installed"], limit=120)
    _print_table("MISSING AUTO-INSTALLABLE TOOLS", b["auto_missing"], limit=120)
    _print_table("MISSING MANUAL / UNSUPPORTED TOOLS", b["manual_missing"], limit=120)
    print("\nReports:", flush=True)
    print("- reports/output/top100-tools/tool-setup-dashboard.md", flush=True)
    print("- reports/output/top100-tools/tool-setup-dashboard.html", flush=True)
    print("- reports/output/top100-tools/top100-status.md", flush=True)


def write_dashboard(rows: list[dict[str, Any]], stage: str = "current", install_result: dict[str, Any] | None = None) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    write_status()
    s = _summary(rows)
    b = _bucket(rows)
    payload = {
        "stage": stage,
        "generated_at": time.time(),
        "summary": s,
        "installed_tools": b["installed"],
        "missing_auto_installable_tools": b["auto_missing"],
        "missing_manual_or_unsupported_tools": b["manual_missing"],
        "safe_runners": b["safe_runners"],
        "install_result": install_result,
        "note": "Autonomous scanning only runs target-scoped safe runners and adaptive safe parameter checks. Aggressive tools remain manual-disabled even when installed.",
    }
    DASH_JSON.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# VulnScope Tool Setup Dashboard",
        "",
        f"Stage: `{stage}`",
        f"Integrated: `{s['total_integrated']}`",
        f"Installed: `{s['installed']}`",
        f"Missing: `{s['missing']}`",
        f"Auto-installable missing: `{s['auto_installable_missing']}`",
        f"Manual / unsupported missing: `{s['manual_or_unsupported_missing']}`",
        f"Safe runners wired: `{s['safe_runners_wired']}`",
        "",
        "## Installed Tools",
    ]
    for r in b["installed"]:
        lines.append(f"- `{int(r['index']):03d}` `{r['name']}` binary=`{r['binary']}` method=`{r.get('install_method')}` mode=`{'safe-runner' if r.get('safe_runner_available') else r.get('profile')}` path=`{r.get('path')}`")
    lines += ["", "## Missing Auto-Installable Tools"]
    for r in b["auto_missing"]:
        lines.append(f"- `{int(r['index']):03d}` `{r['name']}` binary=`{r['binary']}` method=`{r.get('install_method')}` profile=`{r.get('profile')}`")
    lines += ["", "## Missing Manual / Unsupported Tools"]
    for r in b["manual_missing"]:
        lines.append(f"- `{int(r['index']):03d}` `{r['name']}` binary=`{r['binary']}` profile=`{r.get('profile')}` note=`manual install recipe unavailable`")
    if install_result:
        summary = install_result.get("summary", {})
        lines += ["", "## Install Result", f"Attempted: `{summary.get('attempted', 0)}`", f"Installed or repaired: `{summary.get('installed_or_repaired', 0)}`", f"Failed: `{summary.get('failed', 0)}`"]
        for item in install_result.get("results", []):
            lines.append(f"- `{item.get('tool')}` status=`{item.get('status')}` ok=`{item.get('ok')}` path=`{item.get('path') or '-'}` log=`{item.get('log') or '-'}`")
    DASH_MD.write_text("\n".join(lines), encoding="utf-8")

    def table(title: str, data: list[dict[str, Any]]) -> str:
        if not data:
            return f"<section class='card'><h2>{html.escape(title)}</h2><p>None</p></section>"
        rows_html = "".join(
            f"<tr><td>{int(r.get('index', 0)):03d}</td><td>{html.escape(str(r.get('name')))}</td><td>{html.escape(str(r.get('binary')))}</td><td>{html.escape(str(r.get('install_method') or 'manual'))}</td><td>{html.escape(str('safe-runner' if r.get('safe_runner_available') else r.get('profile')))}</td><td>{html.escape(str(r.get('path') or '-'))}</td></tr>"
            for r in data
        )
        return f"<section class='card'><h2>{html.escape(title)} ({len(data)})</h2><table><thead><tr><th>#</th><th>Tool</th><th>Binary</th><th>Install</th><th>Mode</th><th>Path</th></tr></thead><tbody>{rows_html}</tbody></table></section>"

    html_text = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>VulnScope Tool Setup</title><style>body{{margin:0;background:#0b1020;color:#edf3ff;font-family:Arial,sans-serif}}header{{padding:28px;background:#121933;border-bottom:1px solid #2b3765}}main{{padding:24px}}.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:18px}}.metric,.card{{background:#121933;border:1px solid #2b3765;border-radius:16px;padding:16px}}.metric b{{font-size:28px;color:#7aa2ff}}p{{color:#aab6d3}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #2b3765;padding:8px;text-align:left;font-size:13px}}code{{color:#d8e4ff}}@media(max-width:900px){{.stats{{grid-template-columns:1fr 1fr}}table{{font-size:12px}}}}</style></head><body><header><h1>VulnScope Tool Setup Dashboard</h1><p>Stage: <code>{html.escape(stage)}</code></p></header><main><section class='stats'><div class='metric'><b>{s['total_integrated']}</b><p>Integrated</p></div><div class='metric'><b>{s['installed']}</b><p>Installed</p></div><div class='metric'><b>{s['missing']}</b><p>Missing</p></div><div class='metric'><b>{s['auto_installable_missing']}</b><p>Auto-installable</p></div><div class='metric'><b>{s['manual_or_unsupported_missing']}</b><p>Manual</p></div><div class='metric'><b>{s['safe_runners_wired']}</b><p>Safe runners</p></div></section>{table('Installed Tools', b['installed'])}{table('Missing Auto-Installable Tools', b['auto_missing'])}{table('Missing Manual / Unsupported Tools', b['manual_missing'])}</main></body></html>"""
    DASH_HTML.write_text(html_text, encoding="utf-8")
    return payload


def install_missing_supported(rows: list[dict[str, Any]], *, yes: bool = True) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    print("\n" + "═" * 92, flush=True)
    print("INSTALLING ALL MISSING AUTO-INSTALLABLE TOOLS", flush=True)
    print("Recipes include Go, Python, npm, cargo, gem, apt, git-script, and safe wrapper installers.", flush=True)
    print("═" * 92, flush=True)
    payload = install_missing_from_inventory(rows, max_install=100, yes=yes)
    refreshed = build_inventory()
    payload["summary"]["installed_after"] = len([r for r in refreshed if r.get("installed")])
    payload["summary"]["missing_after"] = len([r for r in refreshed if not r.get("installed")])
    INSTALL_LOG.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def run_tool_dashboard_gate(*, interactive: bool = True, assume_yes: bool = False) -> dict[str, Any]:
    rows = build_inventory()
    write_dashboard(rows, stage="before-install")
    show_dashboard(rows, title="VULNSCOPE TOOL SETUP DASHBOARD — BEFORE URL INPUT")

    b = _bucket(rows)
    install_result = None
    if b["auto_missing"]:
        do_install = assume_yes
        if interactive and not assume_yes:
            answer = input("\nInstall all missing auto-installable tools now? [y/N]: ").strip().lower()
            do_install = answer in {"y", "yes"}
        if do_install:
            install_result = install_missing_supported(rows, yes=True)
            rows = build_inventory()
            write_dashboard(rows, stage="after-install", install_result=install_result)
            show_dashboard(rows, title="VULNSCOPE TOOL SETUP DASHBOARD — REFRESHED AFTER INSTALL")
        else:
            print("\n[skip] Tool installation skipped. Current installed tools will be used; missing tools will be skipped safely.", flush=True)
    else:
        print("\n[ok] No auto-installable tools are missing. Proceeding to target input.", flush=True)
    return write_dashboard(build_inventory(), stage="final", install_result=install_result)


def main() -> int:
    parser = argparse.ArgumentParser(description="Show installed/missing Top100 tools before target input and optionally install missing supported tools")
    parser.add_argument("--yes", action="store_true", help="Install auto-installable missing tools without prompting")
    parser.add_argument("--no-prompt", action="store_true", help="Show dashboard only and do not prompt")
    args = parser.parse_args()
    run_tool_dashboard_gate(interactive=not args.no_prompt, assume_yes=args.yes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
