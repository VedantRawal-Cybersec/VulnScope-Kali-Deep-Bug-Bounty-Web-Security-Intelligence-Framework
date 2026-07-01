#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import time
from pathlib import Path
from typing import Any

from cai_error_handler import handled_error, write_json, write_log, write_markdown
from cai_scope_guard import cai_output_dir, host_from_target, normalize_target, scope_policy

CDN_HINTS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "cloudfront": "Amazon CloudFront",
    "edgesuite": "Akamai",
    "azure": "Azure Front Door/CDN",
    "google": "Google Cloud/CDN",
    "incapsula": "Imperva/Incapsula",
    "sucuri": "Sucuri",
    "stackpath": "StackPath",
}
NON_PROD_WORDS = {"dev", "staging", "stage", "test", "qa", "uat", "sandbox", "preprod", "demo", "local"}


def run_command(command: list[str], timeout: int = 18) -> dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return {"status": "ok" if proc.returncode == 0 else "nonzero_exit", "exit_code": proc.returncode, "stdout": proc.stdout[-8000:], "seconds": round(time.time() - started, 2)}
    except FileNotFoundError as exc:
        return handled_error(component="target_profiler", action="run_" + command[0], error=exc, fallback_used="tool_not_installed")
    except subprocess.TimeoutExpired as exc:
        return handled_error(component="target_profiler", action="run_" + command[0], error=exc, fallback_used="timeout_continue")
    except Exception as exc:
        return handled_error(component="target_profiler", action="run_" + command[0], error=exc)


def dns_lookup(host: str) -> dict[str, Any]:
    try:
        records = socket.getaddrinfo(host, None)
        ips = sorted({r[4][0] for r in records if r and r[4]})
        reverse: dict[str, str] = {}
        for ip in ips[:10]:
            try:
                reverse[ip] = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
        return {"status": "ok", "ip_addresses": ips, "reverse_dns": reverse}
    except Exception as exc:
        return handled_error(component="target_profiler", action="dns_lookup", error=exc, fallback_used="dns_unavailable")


def parse_whois(text: str) -> dict[str, Any]:
    name_servers: list[str] = []
    registrar = ""
    org = ""
    created = ""
    updated = ""
    expires = ""
    for raw in text.splitlines():
        line = raw.strip()
        low = line.lower()
        if low.startswith("name server") or low.startswith("nserver"):
            value = line.split(":", 1)[-1].strip().split()[0].strip(".").lower()
            if value and value not in name_servers:
                name_servers.append(value)
        elif low.startswith("registrar:") and not registrar:
            registrar = line.split(":", 1)[-1].strip()
        elif (low.startswith("registrant organization:") or low.startswith("orgname:")) and not org:
            org = line.split(":", 1)[-1].strip()
        elif "creation date" in low and not created:
            created = line.split(":", 1)[-1].strip()
        elif "updated date" in low and not updated:
            updated = line.split(":", 1)[-1].strip()
        elif ("registry expiry date" in low or "expiration date" in low) and not expires:
            expires = line.split(":", 1)[-1].strip()
    return {"registrar": registrar, "organization": org, "created": created, "updated": updated, "expires": expires, "name_servers": name_servers}


def whois_lookup(host: str) -> dict[str, Any]:
    result = run_command(["whois", host], timeout=22)
    if result.get("status") in {"ok", "nonzero_exit"} and result.get("stdout"):
        parsed = parse_whois(str(result.get("stdout") or ""))
        parsed.update({"status": result.get("status"), "seconds": result.get("seconds"), "raw_available": True})
        return parsed
    return {"status": "unavailable", "name_servers": [], "detail": result}


def asn_lookup(ip_addresses: list[str]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for ip in ip_addresses[:6]:
        result = run_command(["whois", "-h", "whois.cymru.com", "-v", ip], timeout=18)
        if result.get("status") == "ok" and result.get("stdout"):
            lines = [x.strip() for x in str(result.get("stdout", "")).splitlines() if x.strip()]
            rows.append({"ip": ip, "status": "ok", "raw": lines[-1] if lines else ""})
        else:
            rows.append({"ip": ip, "status": "unavailable", "detail": result})
    return {"status": "ok" if rows else "no_ips", "rows": rows}


def detect_cdn_waf(profile: dict[str, Any]) -> dict[str, Any]:
    haystack = " ".join(json.dumps(profile, ensure_ascii=False).lower().split())
    matches = sorted({label for hint, label in CDN_HINTS.items() if hint in haystack})
    return {
        "detected": bool(matches),
        "providers": matches,
        "behavior_adjustment": "keep conservative rate limit and prefer passive collectors" if matches else "standard zero-impact profile",
    }


def production_guess(host: str) -> dict[str, Any]:
    parts = {x for x in re.split(r"[.-]+", host.lower()) if x}
    non_prod = sorted(parts & NON_PROD_WORDS)
    if non_prod:
        return {"classification": "staging_or_test_likely", "matched_terms": non_prod, "warning": "Verify authorization and data safety before continuing."}
    return {"classification": "production_likely", "matched_terms": [], "warning": "Treat as production. Only zero-impact modules are enabled."}


def tls_fingerprint(host: str, port: int = 443, timeout: int = 8) -> dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                cipher = ssock.cipher()
                issuer = ", ".join("=".join(x) for group in cert.get("issuer", []) for x in group)
                subject = ", ".join("=".join(x) for group in cert.get("subject", []) for x in group)
                return {
                    "status": "ok",
                    "host": host,
                    "port": port,
                    "tls_version": ssock.version(),
                    "cipher": cipher[0] if cipher else "",
                    "issuer": issuer,
                    "subject": subject,
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }
    except Exception as exc:
        return handled_error(component="target_profiler", action="tls_fingerprint", error=exc, fallback_used="tls_signal_unavailable")


def build_target_profile(target: str, *, include_subdomains: bool = False, tls: bool = True) -> dict[str, Any]:
    target = normalize_target(target)
    host = host_from_target(target)
    write_log(f"building target profile for {host}")
    dns = dns_lookup(host)
    whois = whois_lookup(host)
    asn = asn_lookup(list(dns.get("ip_addresses", []) or [])) if isinstance(dns, dict) else {"status": "skipped"}
    base_profile: dict[str, Any] = {
        "target": target,
        "host": host,
        "generated_at": time.time(),
        "layer": 0,
        "scope_policy": scope_policy(target, include_subdomains=include_subdomains),
        "dns": dns,
        "whois": whois,
        "asn": asn,
        "production_detection": production_guess(host),
        "technologies": [],
    }
    base_profile["waf_cdn"] = detect_cdn_waf(base_profile)
    if base_profile["waf_cdn"].get("providers"):
        base_profile["technologies"].extend(base_profile["waf_cdn"].get("providers", []))
    base_profile["tls"] = tls_fingerprint(host) if tls else {"status": "skipped", "reason": "tls disabled by caller"}
    return base_profile


def write_profile_reports(profile: dict[str, Any]) -> dict[str, Any]:
    out_dir = cai_output_dir(str(profile.get("target") or profile.get("host")))
    write_json(out_dir / "target-profile.json", profile)
    checkpoint = {
        "checkpoint": 0,
        "name": "System Initialization & Target Profiler",
        "status": "completed",
        "target": profile.get("target"),
        "host": profile.get("host"),
        "summary": {
            "ip_count": len(profile.get("dns", {}).get("ip_addresses", []) or []),
            "cdn_waf_detected": profile.get("waf_cdn", {}).get("detected", False),
            "production_classification": profile.get("production_detection", {}).get("classification"),
            "tls_status": profile.get("tls", {}).get("status"),
        },
        "reports": {
            "json": str(out_dir / "target-profile.json"),
            "markdown": str(out_dir / "target-profile.md"),
        },
        "generated_at": time.time(),
    }
    write_json(out_dir / "checkpoint-0.json", checkpoint)
    lines = [
        "# CAI Superior Checkpoint 0 — Target Profile",
        "",
        f"Target: `{profile.get('target')}`",
        f"Host: `{profile.get('host')}`",
        f"Production classification: `{profile.get('production_detection', {}).get('classification')}`",
        f"Production warning: {profile.get('production_detection', {}).get('warning')}",
        f"IP addresses: `{len(profile.get('dns', {}).get('ip_addresses', []) or [])}`",
        f"WAF/CDN detected: `{profile.get('waf_cdn', {}).get('detected')}`",
        f"WAF/CDN providers: `{', '.join(profile.get('waf_cdn', {}).get('providers', []) or []) or 'none observed'}`",
        f"TLS status: `{profile.get('tls', {}).get('status')}`",
        "",
        "## Scope Policy",
        "```json",
        json.dumps(profile.get("scope_policy", {}), indent=2),
        "```",
    ]
    write_markdown(out_dir / "target-profile.md", lines)
    return checkpoint


def main() -> int:
    parser = argparse.ArgumentParser(description="CAI Superior Layer 0 target profiler")
    parser.add_argument("--target", required=True)
    parser.add_argument("--include-subdomains", action="store_true")
    parser.add_argument("--no-tls", action="store_true")
    args = parser.parse_args()
    profile = build_target_profile(args.target, include_subdomains=args.include_subdomains, tls=not args.no_tls)
    checkpoint = write_profile_reports(profile)
    print(json.dumps(checkpoint, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
