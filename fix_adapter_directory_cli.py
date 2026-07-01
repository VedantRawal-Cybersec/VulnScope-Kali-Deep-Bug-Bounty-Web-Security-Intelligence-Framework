#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

HOME = Path.home()
TARGETS = [
    HOME / ".vulnscope" / "tools" / "bin",
    HOME / ".vulnscope" / "tools" / "npm" / "bin",
    HOME / "go" / "bin",
    HOME / ".local" / "bin",
    Path("reports/output/top100-tools"),
    Path("reports/output/top100-tools/install-logs"),
]


def main() -> int:
    results = []
    for path in TARGETS:
        item = {"path": str(path), "ok": False}
        try:
            if path.exists() and not path.is_dir():
                backup = path.with_name(path.name + ".backup")
                path.rename(backup)
                item["renamed_existing_file_to"] = str(backup)
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".vulnscope_write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            item["ok"] = True
        except Exception as exc:
            item["error"] = str(exc)
        results.append(item)
    out = Path("reports/output/top100-tools/adapter-directory-repair.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"results": results}, indent=2), encoding="utf-8")
    print(json.dumps({"results": results, "report": str(out)}, indent=2))
    return 0 if all(x.get("ok") for x in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
