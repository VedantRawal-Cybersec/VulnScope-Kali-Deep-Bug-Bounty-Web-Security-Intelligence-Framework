#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

URL_RE = re.compile(r"https?://[^\s\"'<>]+|/[A-Za-z0-9_./?=&:%-]{2,220}")


class EndpointArtifactImporter:
    """Offline importer for user-supplied endpoint artifacts.

    Reads JSON/text artifacts and extracts URL-like strings into reports and the
    scan state. It does not send network requests.
    """

    def __init__(self, *, state: Any, dashboard: Any | None = None, files: list[str] | None = None) -> None:
        self.state = state
        self.dashboard = dashboard
        self.files = files or []
        self.target = getattr(state, "target", "")
        self.out_dir = Path(getattr(state, "out_dir", "reports/output"))
        self.endpoints: list[str] = []
        self.errors: list[dict[str, str]] = []

    def dash(self, action: str) -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="Endpoint Artifact Import", phase_progress=57, current_agent="EndpointImportAgent", current_tool="endpoint_artifact_import", action=action, endpoint=self.target, safety_status="offline import only")
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO", action)

    def normalize(self, raw: str) -> str:
        raw = raw.strip().rstrip(",.;")
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw
        if raw.startswith("/"):
            return self.target.rstrip("/") + raw
        return ""

    def add(self, endpoint: str) -> None:
        endpoint = self.normalize(endpoint)
        if not endpoint or endpoint in self.endpoints:
            return
        self.endpoints.append(endpoint)
        try:
            self.state.add_url(endpoint, depth=1, source="endpoint-artifact")
        except Exception:
            pass

    def import_file(self, file: str) -> None:
        path = Path(file)
        if not path.exists():
            self.errors.append({"file": file, "error": "file not found"})
            return
        self.dash("Importing endpoint artifact " + path.name)
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in URL_RE.finditer(text):
            self.add(match.group(0))

    def run(self) -> dict[str, Any]:
        for file in self.files:
            self.import_file(file)
        reports = self.write_reports()
        try:
            self.state.stats["endpoint_artifact_imported"] = len(self.endpoints)
            self.state.save()
        except Exception:
            pass
        return {"ok": True, "endpoints": len(self.endpoints), "errors": len(self.errors), "reports": reports}

    def write_reports(self) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": self.files, "endpoints": self.endpoints, "errors": self.errors}
        json_path = self.out_dir / "endpoint-artifact-import.json"
        md_path = self.out_dir / "endpoint-artifact-import.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# Endpoint Artifact Import", "", f"Imported endpoints: `{len(self.endpoints)}`", f"Errors: `{len(self.errors)}`", "", "## Endpoints", ""]
        for endpoint in self.endpoints[:400]:
            lines.append(f"- `{endpoint}`")
        if not self.endpoints:
            lines.append("No endpoints were imported from supplied artifacts.")
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"endpoint_artifact_import_json": str(json_path), "endpoint_artifact_import_md": str(md_path)}
