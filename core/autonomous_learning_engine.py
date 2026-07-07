#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import requests


@dataclass
class LearningRecord:
    source: str
    kind: str
    title: str
    text: str
    url: str = ""
    tags: list[str] | None = None
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        row = asdict(self)
        row["tags"] = self.tags or []
        row["record_id"] = hashlib.sha256((self.source + self.kind + self.title + self.text[:500]).encode("utf-8", "ignore")).hexdigest()[:24]
        row["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return row


class AutonomousLearningEngine:
    """Safe daily-learning layer for VulnScope.

    It ingests public advisories, local scan artifacts, documentation snippets, and
    curated local knowledge into a SQLite FTS index. It does not crawl hidden
    services, rotate identities, bypass controls, run exploit chains, or modify
    targets. Lab-training hooks are metadata only unless a separate local lab
    runner is explicitly invoked by the user.
    """

    DEFAULT_PUBLIC_SOURCES = [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ]

    def __init__(self, *, state: Any | None = None, dashboard: Any | None = None, db_path: str = "data/vulnscope-learning.sqlite3", sources: list[str] | None = None) -> None:
        self.state = state
        self.dashboard = dashboard
        self.target = getattr(state, "target", "") if state is not None else ""
        self.out_dir = Path(getattr(state, "out_dir", "reports/output/learning")) if state is not None else Path("reports/output/learning")
        self.db_path = Path(db_path)
        env_sources = [item.strip() for item in os.getenv("VULNSCOPE_LEARNING_SOURCES", "").split(",") if item.strip()]
        self.sources = sources or env_sources or list(self.DEFAULT_PUBLIC_SOURCES)
        self.records: list[dict[str, Any]] = []
        self.errors: list[dict[str, str]] = []

    def dash(self, action: str, status: str = "running") -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "update"):
            self.dashboard.update(phase="Autonomous Learning", phase_progress=24, current_agent="LearningAgent", current_tool="autonomous_learning", tool_status=status, action=action, endpoint=self.target or "local", evidence="safe learning index update", safety_status="public/local knowledge only • no stealth • no exploitation")
        if self.dashboard is not None and hasattr(self.dashboard, "event"):
            self.dashboard.event("INFO" if status != "failed" else "ERROR", action)

    def connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("CREATE TABLE IF NOT EXISTS learning_records(record_id TEXT PRIMARY KEY, source TEXT, kind TEXT, title TEXT, text TEXT, url TEXT, tags_json TEXT, score REAL, created_at TEXT)")
        try:
            conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS learning_fts USING fts5(record_id, title, text, tags)")
        except Exception:
            pass
        return conn

    @staticmethod
    def short_text(value: Any, limit: int = 4000) -> str:
        text = re.sub(r"\s+", " ", str(value if value is not None else "")).strip()
        return text[:limit]

    def add_record(self, record: LearningRecord) -> None:
        row = record.to_dict()
        self.records.append(row)

    def ingest_public_json(self, url: str) -> None:
        try:
            res = requests.get(url, timeout=12, headers={"User-Agent": "VulnScope-Learning/1.0"})
            if res.status_code != 200:
                self.errors.append({"source": url, "error": f"HTTP {res.status_code}"})
                return
            data = res.json()
        except Exception as exc:
            self.errors.append({"source": url, "error": str(exc)[:400]})
            return
        if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
            for item in data.get("vulnerabilities", [])[:1000]:
                title = str(item.get("cveID") or item.get("name") or "public advisory")
                text = self.short_text(json.dumps(item, ensure_ascii=False, default=str))
                tags = ["public-advisory", "cisa-kev"] if "cveID" in item else ["public-advisory"]
                self.add_record(LearningRecord(source=url, kind="public_advisory", title=title, text=text, url=url, tags=tags, score=1.0))
        else:
            self.add_record(LearningRecord(source=url, kind="public_json", title="public json source", text=self.short_text(json.dumps(data, ensure_ascii=False, default=str)), url=url, tags=["public-json"], score=0.5))

    def ingest_local_reports(self) -> None:
        roots = [Path("reports/output"), Path("logs"), Path("tool_manifests")]
        for root in roots:
            if not root.exists():
                continue
            for path in list(root.rglob("*.md"))[:500] + list(root.rglob("*.json"))[:500]:
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")[:6000]
                except Exception:
                    continue
                if not text.strip():
                    continue
                self.add_record(LearningRecord(source=str(path), kind="local_artifact", title=path.name, text=self.short_text(text), tags=["local", path.suffix.lstrip(".")], score=0.7))

    def ingest_scan_state(self) -> None:
        if self.state is None:
            return
        try:
            coverage = self.state.coverage() if hasattr(self.state, "coverage") else {}
            stats = getattr(self.state, "stats", {}) or {}
            payload = {"target": getattr(self.state, "target", ""), "coverage": coverage, "stats": stats, "findings": getattr(self.state, "findings", [])[:50]}
            self.add_record(LearningRecord(source="current_scan", kind="scan_summary", title="current scan summary", text=self.short_text(json.dumps(payload, ensure_ascii=False, default=str)), tags=["current-scan"], score=0.9))
        except Exception as exc:
            self.errors.append({"source": "current_scan", "error": str(exc)[:400]})

    def write_index(self) -> dict[str, Any]:
        conn = self.connect()
        inserted = 0
        with conn:
            for row in self.records:
                try:
                    conn.execute("INSERT OR REPLACE INTO learning_records(record_id, source, kind, title, text, url, tags_json, score, created_at) VALUES(?,?,?,?,?,?,?,?,?)", (row["record_id"], row["source"], row["kind"], row["title"], row["text"], row.get("url", ""), json.dumps(row.get("tags") or [], ensure_ascii=False), float(row.get("score") or 0), row["created_at"]))
                    try:
                        conn.execute("INSERT OR REPLACE INTO learning_fts(record_id, title, text, tags) VALUES(?,?,?,?)", (row["record_id"], row["title"], row["text"], " ".join(row.get("tags") or [])))
                    except Exception:
                        pass
                    inserted += 1
                except Exception as exc:
                    self.errors.append({"record": row.get("record_id", ""), "error": str(exc)[:300]})
        return {"database": str(self.db_path), "records_seen": len(self.records), "records_written": inserted, "errors": len(self.errors)}

    def query(self, text: str, limit: int = 8) -> list[dict[str, Any]]:
        conn = self.connect()
        rows: list[dict[str, Any]] = []
        try:
            cur = conn.execute("SELECT r.record_id,r.source,r.kind,r.title,snippet(learning_fts,2,'[',']','...',18) AS snippet FROM learning_fts JOIN learning_records r USING(record_id) WHERE learning_fts MATCH ? LIMIT ?", (text, int(limit)))
            for record_id, source, kind, title, snippet in cur.fetchall():
                rows.append({"record_id": record_id, "source": source, "kind": kind, "title": title, "snippet": snippet})
        except Exception:
            tokens = [t.lower() for t in re.findall(r"[a-zA-Z0-9_-]{3,}", text)[:8]]
            if not tokens:
                return []
            cur = conn.execute("SELECT record_id,source,kind,title,text FROM learning_records ORDER BY created_at DESC LIMIT 500")
            for record_id, source, kind, title, body in cur.fetchall():
                hay = (title + " " + body).lower()
                if any(t in hay for t in tokens):
                    rows.append({"record_id": record_id, "source": source, "kind": kind, "title": title, "snippet": body[:500]})
                if len(rows) >= limit:
                    break
        return rows

    def write_reports(self, summary: dict[str, Any]) -> dict[str, str]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"target": self.target, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "summary": summary, "sources": self.sources, "errors": self.errors, "sample_records": self.records[:20], "policy": "safe public/local learning only; no stealth, no exploit automation, no credential attacks"}
        json_path = self.out_dir / "autonomous-learning.json"
        md_path = self.out_dir / "autonomous-learning.md"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["# Autonomous Learning", "", f"Target: `{self.target or 'local'}`", f"Database: `{summary.get('database')}`", f"Records written: `{summary.get('records_written')}`", f"Errors: `{summary.get('errors')}`", "", "## Sources"]
        for src in self.sources:
            lines.append(f"- `{src}`")
        lines.extend(["", "## Policy", payload["policy"]])
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return {"autonomous_learning_json": str(json_path), "autonomous_learning_md": str(md_path), "autonomous_learning_db": str(self.db_path)}

    def run(self) -> dict[str, Any]:
        if os.getenv("VULNSCOPE_DISABLE_LEARNING", "0") == "1":
            reports = self.write_reports({"database": str(self.db_path), "records_written": 0, "errors": 0, "disabled": True})
            return {"ok": True, "skipped": True, "reason": "disabled", "reports": reports}
        self.dash("Updating safe learning index")
        if os.getenv("VULNSCOPE_OFFLINE_LEARNING_ONLY", "0") != "1":
            for source in self.sources[:20]:
                if source.startswith("http://") or source.startswith("https://"):
                    self.ingest_public_json(source)
        self.ingest_local_reports()
        self.ingest_scan_state()
        summary = self.write_index()
        reports = self.write_reports(summary)
        if self.state is not None:
            try:
                self.state.stats["learning_records_written"] = summary.get("records_written", 0)
                self.state.save()
            except Exception:
                pass
        self.dash("Autonomous learning index updated", status="completed")
        return {"ok": True, **summary, "reports": reports}
