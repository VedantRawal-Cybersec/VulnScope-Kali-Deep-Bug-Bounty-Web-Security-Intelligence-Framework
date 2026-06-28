#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ai.finding_discovery import _build_prompt, _configured_providers, _parse_json_safely
from ai.local_env import load_local_ai_env
from ai.provider_clients import AIProviderClient
from ai.ai_guardrails import redact_secrets

VERSION = "0.1.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI Discovery Engine for VulnScope evidence")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--input", default="reports/output/evidence.json", help="VulnScope evidence JSON or text file")
    parser.add_argument("--providers", default="", help="Comma-separated providers: openai,gemini,groq,openrouter. Default: auto-detect")
    parser.add_argument("--output-dir", default="reports/output/ai-discovery")
    return parser.parse_args()


def parse_providers(raw: str) -> list[str] | None:
    if not raw.strip():
        return None
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def load_payload(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(text)
    except Exception:
        data = {"raw_text": text[:40000]}
    return redact_secrets(data)


def main() -> int:
    load_local_ai_env()
    args = parse_args()
    if args.version:
        print(f"AI Discovery CLI {VERSION}")
        return 0

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Input not found: {input_path}")
        return 1

    providers = parse_providers(args.providers) or _configured_providers()
    if not providers:
        print("[!] No AI providers configured. Run: python3 vulnscope.py --setup-ai-keys")
        return 1

    payload = load_payload(input_path)
    prompt = _build_prompt(payload)
    client = AIProviderClient()
    results = []
    merged_findings = []

    for provider in providers:
        result = client.call(provider, prompt)
        parsed = _parse_json_safely(result.text)
        results.append({
            "provider": provider,
            "ok": result.ok,
            "error": result.error,
            "parsed": parsed,
            "raw_text": result.text[:8000] if result.text else "{}",
        })
        if isinstance(parsed, dict):
            merged_findings.extend(parsed.get("discovered_findings", []))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ai-discovery-results.json").write_text(json.dumps(redact_secrets({"providers": providers, "results": results, "merged_findings": merged_findings}), indent=2, ensure_ascii=False), encoding="utf-8")
    (output_dir / "ai-discovery-report.md").write_text(build_markdown_report(merged_findings, results), encoding="utf-8")

    print("[+] AI Discovery completed")
    print(f"[+] Providers: {', '.join(providers)}")
    print(f"[+] AI-discovered candidates: {len(merged_findings)}")
    print(f"[+] JSON: {output_dir}/ai-discovery-results.json")
    print(f"[+] Report: {output_dir}/ai-discovery-report.md")
    return 0


def build_markdown_report(findings: list[dict[str, Any]], results: list[dict[str, Any]]) -> str:
    lines = ["# AI Discovery Report", "", "AI Discovery scans redacted evidence and proposes additional manual-review candidates. It does not confirm vulnerabilities without proof.", "", "## Provider Status", ""]
    for item in results:
        lines.append(f"- **{item.get('provider')}**: {'ok' if item.get('ok') else 'failed'} {item.get('error') or ''}")
    lines += ["", "## Discovered Candidates", ""]
    if not findings:
        lines.append("No additional AI-discovered candidates were returned.")
    for idx, finding in enumerate(findings, start=1):
        lines += [
            f"### AI-{idx:03d} - {finding.get('title', 'Candidate')}",
            f"- Category: {finding.get('category')}",
            f"- Status: {finding.get('status')}",
            f"- Severity: {finding.get('severity')}",
            f"- Confidence: {finding.get('confidence')}",
            f"- Endpoint: `{finding.get('affected_endpoint')}`",
            f"- Parameter: `{finding.get('parameter')}`",
            f"- Why it may matter: {finding.get('why_it_may_matter')}",
            "- Evidence seen:",
        ]
        for evidence in finding.get("evidence_seen", [])[:6]:
            lines.append(f"  - {evidence}")
        lines.append("- Safe validation steps:")
        for step in finding.get("safe_validation_steps", [])[:8]:
            lines.append(f"  - {step}")
        lines.append("- Required proof:")
        for proof in finding.get("required_proof", [])[:8]:
            lines.append(f"  - {proof}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
