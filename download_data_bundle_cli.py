#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from target_scope_guard import normalize_target

OUT = Path("reports/output/download-bundles")

REPORT_PATHS = [
    "reports/output/current-target-session.json",
    "reports/output/kai-interface/direct-session.json",
    "reports/output/kai-interface/scan-dashboard-selection.json",
    "reports/output/kai-interface/scan-dashboard-selection.md",
    "reports/output/autonomous-live/live-run.md",
    "reports/output/autonomous-live/live-run.json",
    "reports/output/mission-verdicts/mission-verdicts.md",
    "reports/output/mission-verdicts/mission-verdicts.json",
    "reports/output/evidence-cards/evidence-cards.md",
    "reports/output/evidence-cards/evidence-cards.json",
    "reports/output/reportability/reportability.md",
    "reports/output/reportability/reportability.json",
    "reports/output/normalized/normalized-evidence.md",
    "reports/output/normalized/normalized-evidence.json",
    "reports/output/report-v2/executive-report-v2.md",
    "reports/output/vulnscope-main/final-summary.md",
    "reports/output/top100-tools/top100-status.md",
    "reports/output/top100-tools/top100-status.json",
]


def host_from_target(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = parsed.hostname or parsed.netloc or target
    return host.split(":")[0].lower().strip()


def domain_slug(target: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", host_from_target(target)).strip("-.") or "target"


def add_path(zf: zipfile.ZipFile, path: Path, base: Path, added: list[str]) -> None:
    if not path.exists():
        return
    if path.is_file():
        rel = path.relative_to(base) if path.is_relative_to(base) else path
        zf.write(path, rel.as_posix())
        added.append(rel.as_posix())
        return
    for item in path.rglob("*"):
        if item.is_file() and item.stat().st_size <= 5_000_000:
            rel = item.relative_to(base) if item.is_relative_to(base) else item
            zf.write(item, rel.as_posix())
            added.append(rel.as_posix())


def build_bundle(target: str) -> dict[str, object]:
    target = normalize_target(target)
    slug = domain_slug(target)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    OUT.mkdir(parents=True, exist_ok=True)
    zip_path = OUT / f"{slug}-{stamp}-data-bundle.zip"
    latest_path = OUT / f"{slug}-latest-data-bundle.zip"
    manifest_path = OUT / f"{slug}-{stamp}-bundle-manifest.json"
    base = Path(".").resolve()
    added: list[str] = []

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for raw in REPORT_PATHS:
            add_path(zf, Path(raw), base, added)
        add_path(zf, Path("reports/output/domain-reports") / f"{slug}-finding-brief.md", base, added)
        add_path(zf, Path("reports/output/domain-reports") / f"{slug}-finding-brief.json", base, added)
        add_path(zf, Path("reports/output/top100-tools") / slug, base, added)
        add_path(zf, Path("reports/output/autonomous-live/module-logs"), base, added)

        manifest = {
            "target": target,
            "host": host_from_target(target),
            "created_at": time.time(),
            "bundle": str(zip_path),
            "files_count": len(added),
            "files": sorted(set(added)),
            "note": "This bundle contains scan data and reports only, not the VulnScope source code.",
        }
        zf.writestr("bundle-manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))

    latest_path.write_bytes(zip_path.read_bytes())
    manifest_path.write_text(json.dumps({"target": target, "bundle": str(zip_path), "latest": str(latest_path), "files_count": len(added), "files": sorted(set(added))}, indent=2), encoding="utf-8")

    md_path = OUT / f"{slug}-{stamp}-bundle-summary.md"
    md_path.write_text("\n".join([
        f"# VulnScope Data Bundle — {host_from_target(target)}",
        "",
        f"Target: `{target}`",
        f"Files included: `{len(set(added))}`",
        f"Run bundle: `{zip_path}`",
        f"Latest bundle: `{latest_path}`",
        f"Manifest: `{manifest_path}`",
        "",
        "This is a data-only export for the selected website scan. It does not contain the tool source code.",
    ]), encoding="utf-8")

    return {"target": target, "bundle": str(zip_path), "latest": str(latest_path), "manifest": str(manifest_path), "summary": str(md_path), "files_count": len(set(added))}


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a per-domain downloadable scan data bundle")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    result = build_bundle(args.target)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
