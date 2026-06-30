#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import time
from pathlib import Path
from typing import Any

from force_top100_operational_cli import force_all_tools_operational
from top100_integrator_cli import build_inventory, write_status
from universal_tool_installer import install_missing_from_inventory, is_adapter

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
    adapters = [r for r in installed if is_adapter(str(r.get("path") or ""))]
    real_installed = [r for r in installed if not is_adapter(str(r.get("path") or ""))]
    return {
        "installed": installed,
        "real_installed": real_installed,
        "adapters": adapters,
        "missing": missing,
        "auto_missing": auto_missing,
        "manual_missing": manual_missing,
        "safe_runners": safe_runners,
    }


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    b = _bucket(rows)
    return {
        "total_integrated": len(rows),
        "installed_or_operational": len(b["installed"]),
        "real_native_tools": len(b["real_installed"]),
        "safe_adapters": len(b["adapters"]),
        "missing": len(b["missing"]),
        "auto_installable_missing": len(b["auto_missing"]),
        "manual_or_unsupported_missing": len(b["manual_missing"]),
        "safe_runners_wired": len(b["safe_runners"]),
    }


def _line() -> None:
    print("─" * 100, flush=True)


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
        path = str(r.get("path") or "-")
        adapter = "ADAPTER" if is_adapter(path) else "REAL"
        mode = "SAFE-RUNNER" if r.get("safe_runner_available") else str(r.get("profile", ""))
        print(f"{idx:03d}  {name:<24} binary={binary:<18} type={adapter:<7} method={method:<13} mode={mode:<18} path={path}", flush=True)
    if limit and len(rows) > limit:
        print(f"... {len(rows) - limit} more shown in reports/output/top100-tools/tool-setup-dashboard.md", flush=True)


def show_dashboard(rows: list[dict[str, Any]], *, title: str = "VULNSCOPE TOOL SETUP DASHBOARD") -> None:
    s = _summary(rows)
    b = _bucket(rows)
    print("\n" + "═" * 100, flush=True)
    print(title, flush=True)
    print("Tools are checked before URL input. Failed native installs are repaired with safe adapters.", flush=True)
    print("═" * 100, flush=True)
    print(
        f"Integrated: {s['total_integrated']} | Operational: {s['installed_or_operational']} | Missing: {s['missing']} | "
        f"Real native: {s['real_native_tools']} | Safe adapters: {s['safe_adapters']} | Safe runners: {s['safe_runners_wired']}",
        flush=True,
    )
    _print_table("REAL INSTALLED TOOLS", b["real_installed"], limit=120)
    _print_table("VULNSCOPE SAFE ADAPTERS", b["adapters"], limit=120)
    _print_table("MISSING TOOLS", b["missing"], limit=120)
    print("\nReports:", flush=True)
    print("- reports/output/top100-tools/tool-setup-dashboard.md", flush=True)
    print("- reports/output/top100-tools/tool-setup-dashboard.html", flush=True)
    print("- reports/output/top100-tools/force-operational.md", flush=True)
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
        "real_installed_tools": b["real_installed"],
        "safe_adapters": b["adapters"],
        "missing_tools": b["missing"],
        "safe_runners": b["safe_runners"],
        "install_result": install_result,
        "note": "Native upstream installs are preferred. Safe adapters are used only for failed/missing tools so the autonomous workflow does not crash.",
    }
    DASH_JSON.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# VulnScope Tool Setup Dashboard",
        "",
        f"Stage: `{stage}`",
        f"Integrated: `{s['total_integrated']}`",
        f"Operational: `{s['installed_or_operational']}`",
        f"Missing: `{s['missing']}`",
        f"Real native tools: `{s['real_native_tools']}`",
        f"Safe adapters: `{s['safe_adapters']}`",
        f"Safe runners wired: `{s['safe_runners_wired']}`",
        "",
        "## Real Installed Tools",
    ]
    for r in b["real_installed"]:
        lines.append(f"- `{int(r['index']):03d}` `{r['name']}` binary=`{r['binary']}` method=`{r.get('install_method')}` path=`{r.get('path')}`")
    lines += ["", "## VulnScope Safe Adapters"]
    for r in b["adapters"]:
        lines.append(f"- `{int(r['index']):03d}` `{r['name']}` binary=`{r['binary']}` method=`{r.get('install_method')}` path=`{r.get('path')}`")
    lines += ["", "## Missing Tools"]
    if not b["missing"]:
        lines.append("None")
    for r in b["missing"]:
        lines.append(f"- `{int(r['index']):03d}` `{r['name']}` binary=`{r['binary']}` method=`{r.get('install_method')}`")
    if install_result:
        summary = install_result.get("summary", {})
        lines += [
            "",
            "## Install / Repair Result",
            f"Attempted: `{summary.get('attempted', 0)}`",
            f"Installed or repaired: `{summary.get('installed_or_repaired', 0)}`",
            f"Real tools from this run: `{summary.get('real_tools', 0)}`",
            f"Safe adapters from this run: `{summary.get('safe_adapters', 0)}`",
            f"Failed: `{summary.get('failed', 0)}`",
            f"Missing after: `{summary.get('missing_after', 0)}`",
        ]
        for item in install_result.get("results", []):
            lines.append(f"- `{item.get('tool')}` status=`{item.get('status')}` ok=`{item.get('ok')}` real=`{item.get('real_tool')}` adapter=`{item.get('adapter')}` path=`{item.get('path') or '-'}` log=`{item.get('log') or '-'}`")
    DASH_MD.write_text("\n".join(lines), encoding="utf-8")

    def table(title: str, data: list[dict[str, Any]]) -> str:
        if not data:
            return f"<section class='card'><h2>{html.escape(title)}</h2><p>None</p></section>"
        rows_html = "".join(
            f"<tr><td>{int(r.get('index', 0)):03d}</td><td>{html.escape(str(r.get('name')))}</td><td>{html.escape(str(r.get('binary')))}</td><td>{'Adapter' if is_adapter(str(r.get('path') or '')) else 'Real'}</td><td>{html.escape(str(r.get('install_method') or 'manual'))}</td><td>{html.escape(str(r.get('path') or '-'))}</td></tr>"
            for r in data
        )
        return f"<section class='card'><h2>{html.escape(title)} ({len(data)})</h2><table><thead><tr><th>#</th><th>Tool</th><th>Binary</th><th>Type</th><th>Method</th><th>Path</th></tr></thead><tbody>{rows_html}</tbody></table></section>"

    html_text = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>VulnScope Tool Setup</title><style>body{{margin:0;background:#0b1020;color:#edf3ff;font-family:Arial,sans-serif}}header{{padding:28px;background:#121933;border-bottom:1px solid #2b3765}}main{{padding:24px}}.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:18px}}.metric,.card{{background:#121933;border:1px solid #2b3765;border-radius:16px;padding:16px}}.metric b{{font-size:28px;color:#7aa2ff}}p{{color:#aab6d3}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #2b3765;padding:8px;text-align:left;font-size:13px}}code{{color:#d8e4ff}}@media(max-width:900px){{.stats{{grid-template-columns:1fr 1fr}}table{{font-size:12px}}}}</style></head><body><header><h1>VulnScope Tool Setup Dashboard</h1><p>Stage: <code>{html.escape(stage)}</code></p></header><main><section class='stats'><div class='metric'><b>{s['total_integrated']}</b><p>Integrated</p></div><div class='metric'><b>{s['installed_or_operational']}</b><p>Operational</p></div><div class='metric'><b>{s['missing']}</b><p>Missing</p></div><div class='metric'><b>{s['real_native_tools']}</b><p>Real native</p></div><div class='metric'><b>{s['safe_adapters']}</b><p>Safe adapters</p></div><div class='metric'><b>{s['safe_runners_wired']}</b><p>Safe runners</p></div></section>{table('Real Installed Tools', b['real_installed'])}{table('VulnScope Safe Adapters', b['adapters'])}{table('Missing Tools', b['missing'])}</main></body></html>"""
    DASH_HTML.write_text(html_text, encoding="utf-8")
    return payload


def install_missing_supported(rows: list[dict[str, Any]], *, yes: bool = True) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    print("\n" + "═" * 100, flush=True)
    print("INSTALLING + FORCE-REPAIRING ALL MISSING TOP100 TOOLS", flush=True)
    print("Step 1: try real native installers. Step 2: create safe adapters for anything that still fails.", flush=True)
    print("═" * 100, flush=True)
    payload = install_missing_from_inventory(rows, max_install=100, yes=yes)
    force_payload = force_all_tools_operational(reason="native install failed during tool setup dashboard")
    refreshed = build_inventory()
    payload["force_operational"] = force_payload
    payload["summary"]["installed_after"] = len([r for r in refreshed if r.get("installed")])
    payload["summary"]["missing_after"] = len([r for r in refreshed if not r.get("installed")])
    payload["summary"]["safe_adapters_after"] = len([r for r in refreshed if is_adapter(str(r.get("path") or ""))])
    INSTALL_LOG.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def run_tool_dashboard_gate(*, interactive: bool = True, assume_yes: bool = False) -> dict[str, Any]:
    rows = build_inventory()
    write_dashboard(rows, stage="before-install")
    show_dashboard(rows, title="VULNSCOPE TOOL SETUP DASHBOARD — BEFORE URL INPUT")

    missing = [r for r in rows if not r.get("installed")]
    install_result = None
    if missing:
        do_install = assume_yes
        if interactive and not assume_yes:
            answer = input("\nInstall/repair all missing Top100 tools now? [y/N]: ").strip().lower()
            do_install = answer in {"y", "yes"}
        if do_install:
            install_result = install_missing_supported(rows, yes=True)
            rows = build_inventory()
            write_dashboard(rows, stage="after-install-and-force-repair", install_result=install_result)
            show_dashboard(rows, title="VULNSCOPE TOOL SETUP DASHBOARD — REFRESHED AFTER INSTALL/REPAIR")
        else:
            print("\n[skip] Tool repair skipped. Current installed tools will be used; missing tools will be skipped safely.", flush=True)
    else:
        print("\n[ok] All Top100 tools are already operational. Proceeding to target input.", flush=True)
    return write_dashboard(build_inventory(), stage="final", install_result=install_result)


def main() -> int:
    parser = argparse.ArgumentParser(description="Show installed/missing Top100 tools before target input and optionally install/repair missing tools")
    parser.add_argument("--yes", action="store_true", help="Install/repair missing tools without prompting")
    parser.add_argument("--no-prompt", action="store_true", help="Show dashboard only and do not prompt")
    args = parser.parse_args()
    run_tool_dashboard_gate(interactive=not args.no_prompt, assume_yes=args.yes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
