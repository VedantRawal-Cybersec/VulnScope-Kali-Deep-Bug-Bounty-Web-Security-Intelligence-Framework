#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from core.evidence_store import EvidenceStore
from core.http_client_v2 import SafeHttpClientV2
from core.safe_surface_engine import SafeSurfaceEngine
from core.scan_state import ScanState
from core.test_engine import TestEngine


class MiniApp(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _send(self, body: str, *, content_type: str = "text/html", code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/robots.txt":
            return self._send("User-agent: *\nAllow: /profile?id=1\nSitemap: /sitemap.xml\n", content_type="text/plain")
        if parsed.path == "/sitemap.xml":
            return self._send("<urlset><url><loc>http://127.0.0.1:%d/search?q=test</loc></url></urlset>" % self.server.server_address[1], content_type="application/xml")
        if parsed.path == "/app.js":
            return self._send("fetch('/api/items?id=1'); const route='/details?item=1';", content_type="application/javascript")
        if parsed.path == "/api/items":
            return self._send(json.dumps({"ok": True, "id": query.get("id", [""])[0]}), content_type="application/json")
        if parsed.path in {"/", "/index.html"}:
            port = self.server.server_address[1]
            return self._send(f"""
<html><head><script src="/app.js"></script></head>
<body>
<a href="/profile?id=1">profile</a>
<a href="/search?q=test">search</a>
<form method="GET" action="/lookup"><input name="id" value="1"><input name="q" value="test"></form>
</body></html>
""")
        return self._send("<html><body>ok %s</body></html>" % self.path)


def run_smoke() -> dict:
    server = ThreadingHTTPServer(("127.0.0.1", 0), MiniApp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_address[1]}/"
    old_cwd = Path.cwd()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        try:
            state = ScanState(target, resume=False)
            evidence = EvidenceStore(target)
            client = SafeHttpClientV2(state=state, evidence=evidence, timeout=5, delay=0, request_budget=200)
            tester = TestEngine(state=state, client=client, dashboard=None)
            result = SafeSurfaceEngine(state=state, client=client, tester=tester, dashboard=None, max_pages=60, max_depth=3, max_params=50, mode="safe-active", include_subdomains=False).run_all()
            payload = {"target": target, "result": result, "urls": len(state.urls), "params": len(state.params), "tests": len(state.tests), "findings": len(state.findings), "reports": result.get("reports", {})}
        finally:
            os.chdir(old_cwd)
            server.shutdown()
    payload["ok"] = payload["urls"] >= 5 and payload["params"] >= 3 and payload["tests"] >= 3
    return payload


if __name__ == "__main__":
    out = run_smoke()
    print(json.dumps(out, indent=2, ensure_ascii=False))
    raise SystemExit(0 if out.get("ok") else 1)
