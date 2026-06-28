#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

DEFAULT_REPORT_PATHS = [
    Path("reports/output/target-report.md"),
    Path("reports/output/evidence.json"),
    Path("reports/output/autopilot-environment.json"),
    Path("reports/output/mythic/mythic-report.md"),
    Path("reports/output/mythic/mythic-evidence.json"),
    Path("reports/output/mythic/mythic-proof-exports.md"),
    Path("reports/output/mythic/mythic-acceptance-tests.json"),
    Path("reports/output/uplift/uplift-report.md"),
    Path("reports/output/uplift/uplift-evidence.json"),
    Path("reports/output/uplift/defensive-exports.txt"),
    Path("reports/output/ai-discovery/ai-discovery-report.md"),
    Path("reports/output/ai-discovery/ai-discovery-results.json"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export VulnScope reports to a local downloadable ZIP package")
    parser.add_argument("--output", default="", help="Custom ZIP output path. Default: ~/Downloads/vulnscope-report-pack-<timestamp>.zip")
    parser.add_argument("--source", default="reports/output", help="Report output directory to package")
    parser.add_argument("--open-folder", action="store_true", help="Open the export folder after creating the ZIP when desktop tools are available")
    parser.add_argument("--list", action="store_true", help="List report files that would be exported")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_dir = Path(args.source)
    files = collect_report_files(source_dir)

    if args.list:
        if not files:
            print("[!] No report files found yet. Run a scan first.")
            return 1
        print("Report files available for export:")
        for file in files:
            print(f"- {file}")
        return 0

    if not files:
        print("[!] No report files found. Run VulnScope/Mythic/Uplift/AI Discovery first.")
        print("Example:")
        print("  python3 vulnscope.py --url https://example.com --mode passive --max-pages 5")
        return 1

    output_path = Path(args.output).expanduser() if args.output else default_output_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with ZipFile(output_path, "w", compression=ZIP_DEFLATED) as zipf:
        for file in files:
            arcname = file.relative_to(Path.cwd()) if file.is_absolute() and Path.cwd() in file.parents else file
            zipf.write(file, arcname=str(arcname))

    print("[+] Report package created successfully")
    print(f"[+] ZIP file: {output_path}")
    print(f"[+] Files included: {len(files)}")
    print("[+] You can now open your file manager and download/copy/share this ZIP.")

    if args.open_folder:
        open_folder(output_path.parent)
    return 0


def collect_report_files(source_dir: Path) -> list[Path]:
    candidates: list[Path] = []
    for path in DEFAULT_REPORT_PATHS:
        if path.exists() and path.is_file():
            candidates.append(path)
    if source_dir.exists():
        for suffix in ("*.md", "*.json", "*.txt", "*.html", "*.csv"):
            candidates.extend(source_dir.rglob(suffix))
    unique = []
    seen = set()
    for file in candidates:
        resolved = file.resolve()
        if resolved not in seen and file.exists() and file.is_file():
            seen.add(resolved)
            unique.append(file)
    return sorted(unique, key=lambda p: str(p))


def default_output_path() -> Path:
    downloads = Path.home() / "Downloads"
    if not downloads.exists():
        downloads = Path.home()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return downloads / f"vulnscope-report-pack-{stamp}.zip"


def open_folder(path: Path) -> None:
    commands = [["xdg-open", str(path)], ["gio", "open", str(path)]]
    for command in commands:
        if shutil.which(command[0]):
            try:
                subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except Exception:
                continue
    print(f"[!] Could not open folder automatically. Open manually: {path}")


if __name__ == "__main__":
    raise SystemExit(main())
