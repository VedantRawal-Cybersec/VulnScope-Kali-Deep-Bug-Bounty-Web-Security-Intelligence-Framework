#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from top100_integrator_cli import build_inventory, write_status
from universal_tool_installer import install_one

OUT = Path("reports/output/top100-tools")
DEFAULT_REPAIR_TOOLS = [
    "wappalyzer",
    "gitleaks",
    "trufflehog",
    "mantra",
    "jsluice",
    "trivy",
    "grype",
    "osv-scanner",
]


def row_map() -> dict[str, dict[str, Any]]:
    return {str(r.get("name")): r for r in build_inventory()}


def repair_tools(names: list[str]) -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = row_map()
    results: list[dict[str, Any]] = []
    started = time.time()
    print("=" * 84, flush=True)
    print("VULNSCOPE FAILED TOOL REPAIR", flush=True)
    print("Repairing failed/missing tools with release, npm-wrapper, Go, apt, pip, cargo, and gem recipes.", flush=True)
    print("=" * 84, flush=True)
    for index, name in enumerate(names, 1):
        row = rows.get(name, {"name": name, "binary": name})
        binary = str(row.get("binary") or name)
        installed_before = bool(row.get("installed"))
        if installed_before:
            result = {"tool": name, "binary": binary, "ok": True, "status": "already_installed", "path": row.get("path"), "seconds": 0.0}
            print(f"[{index:02d}/{len(names):02d}] {name} already installed -> {row.get('path')}", flush=True)
        else:
            print(f"[{index:02d}/{len(names):02d}] repairing {name} ...", flush=True)
            result = install_one(name, binary, yes=True)
            print(f"      status={result.get('status')} ok={result.get('ok')} path={result.get('path') or '-'} log={result.get('log')}", flush=True)
        results.append(result)

    write_status()
    refreshed = build_inventory()
    payload = {
        "generated_at": time.time(),
        "summary": {
            "attempted": len(results),
            "repaired_or_present": len([r for r in results if r.get("ok")]),
            "failed": len([r for r in results if not r.get("ok")]),
            "installed_after": len([r for r in refreshed if r.get("installed")]),
            "missing_after": len([r for r in refreshed if not r.get("installed")]),
            "seconds": round(time.time() - started, 2),
        },
        "results": results,
    }
    (OUT / "failed-tool-repair.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# Failed Tool Repair Report",
        "",
        f"Attempted: `{payload['summary']['attempted']}`",
        f"Repaired or present: `{payload['summary']['repaired_or_present']}`",
        f"Failed: `{payload['summary']['failed']}`",
        f"Installed after: `{payload['summary']['installed_after']}`",
        f"Missing after: `{payload['summary']['missing_after']}`",
        "",
        "## Results",
    ]
    for r in results:
        lines.append(f"- `{r.get('tool')}` status=`{r.get('status')}` ok=`{r.get('ok')}` path=`{r.get('path') or '-'}` log=`{r.get('log') or '-'}`")
    (OUT / "failed-tool-repair.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"summary": payload["summary"], "report": "reports/output/top100-tools/failed-tool-repair.md"}, indent=2), flush=True)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Repair failed VulnScope Top100 tool installs")
    parser.add_argument("tools", nargs="*", help="Specific tools to repair. Defaults to known failed tools from the latest installer run.")
    args = parser.parse_args()
    repair_tools(args.tools or DEFAULT_REPAIR_TOOLS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
