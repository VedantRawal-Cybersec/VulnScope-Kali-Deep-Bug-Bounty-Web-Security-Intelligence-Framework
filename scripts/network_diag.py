#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def normalize(url: str) -> str:
    raw = str(url or "").strip()
    return raw if "://" in raw else "https://" + raw


def dns_lookup(host: str) -> dict:
    started = time.time()
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({item[4][0] for item in infos})
        return {"ok": True, "ips": ips, "elapsed_ms": int((time.time() - started) * 1000)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "elapsed_ms": int((time.time() - started) * 1000)}


def tcp_connect(host: str, port: int, timeout: float) -> dict:
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "elapsed_ms": int((time.time() - started) * 1000)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "elapsed_ms": int((time.time() - started) * 1000)}


def http_request(url: str, timeout: float) -> dict:
    started = time.time()
    try:
        req = Request(url, method="GET", headers={"User-Agent": "VulnScope-NetworkDiag/1.0"})
        context = ssl.create_default_context()
        with urlopen(req, timeout=timeout, context=context) as response:
            body = response.read(512)
            return {
                "ok": True,
                "status": int(response.status),
                "final_url": response.geturl(),
                "content_type": response.headers.get("Content-Type", ""),
                "sample_bytes": len(body),
                "elapsed_ms": int((time.time() - started) * 1000),
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "elapsed_ms": int((time.time() - started) * 1000)}


def run_cmd(cmd: list[str], timeout: int = 8) -> dict:
    started = time.time()
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode, "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-2000:], "elapsed_ms": int((time.time() - started) * 1000)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "elapsed_ms": int((time.time() - started) * 1000)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose whether VulnScope/Kali can reach a target before scanning.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", default="logs/network_diagnostics.json")
    args = parser.parse_args()

    target = normalize(args.target)
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        print("Invalid target", file=sys.stderr)
        return 2

    payload = {
        "target": target,
        "host": host,
        "port": port,
        "dns": dns_lookup(host),
        "tcp": tcp_connect(host, port, args.timeout),
        "http": http_request(target, args.timeout),
        "curl": run_cmd(["curl", "-I", "--max-time", str(int(args.timeout)), target]),
        "recommendations": [],
    }

    if not payload["dns"].get("ok"):
        payload["recommendations"].append("DNS failed. Check /etc/resolv.conf, VPN, proxy, or try: dig <host> / nslookup <host>.")
    if payload["dns"].get("ok") and not payload["tcp"].get("ok"):
        payload["recommendations"].append("TCP connect failed. Check internet, firewall, proxy, VPN, route, or target port availability.")
    if payload["tcp"].get("ok") and not payload["http"].get("ok"):
        payload["recommendations"].append("TCP works but HTTP failed. Check scheme http/https, redirects, TLS inspection, proxy, or target rate limiting.")
    if payload["http"].get("ok"):
        payload["recommendations"].append("Target is reachable from this machine. Run VulnScope with same scheme and optional seed URLs.")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"\nWrote: {out}")
    return 0 if payload["http"].get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
