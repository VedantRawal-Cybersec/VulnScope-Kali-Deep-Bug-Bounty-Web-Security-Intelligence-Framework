from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ai.ai_guardrails import build_ai_safety_instruction, redact_secrets
from ai.local_env import load_local_ai_env
from ai.provider_clients import AIProviderClient
from core.evidence_store import EvidenceStore, Finding


def run_ai_finding_review(
    store: EvidenceStore,
    providers: list[str] | None = None,
    max_findings: int = 12,
) -> None:
    """Run optional AI review on collected findings.

    The AI review is disabled unless the CLI asks for it. Evidence is redacted
    before leaving the local machine. Results are advisory only.
    """
    load_local_ai_env()
    providers = providers or _configured_providers()
    if not providers:
        store.metadata["ai_review"] = {
            "enabled": False,
            "reason": "No AI providers requested or configured. Run: python3 vulnscope.py --setup-ai-keys",
        }
        return

    client = AIProviderClient()
    target_findings = store.findings[:max_findings]
    if not target_findings:
        store.metadata["ai_review"] = {"enabled": True, "reviews": [], "note": "No findings to review"}
        return

    compact_evidence = _build_compact_review_payload(target_findings, store.metadata)
    prompt = _build_prompt(compact_evidence)

    reviews: list[dict[str, Any]] = []
    for provider in providers:
        result = client.call(provider, prompt)
        reviews.append(
            {
                "provider": provider,
                "ok": result.ok,
                "error": result.error,
                "raw_text": _safe_text(result.text),
            }
        )

    store.metadata["ai_review"] = {
        "enabled": True,
        "providers": providers,
        "reviewed_findings": len(target_findings),
        "reviews": reviews,
        "advisory_only": True,
        "safety_note": "AI review is advisory. It must not auto-enable exploit logic or replace manual validation.",
    }

    store.add_finding(
        Finding(
            finding_id=store.next_finding_id(),
            title="AI Analyst Review Completed",
            category="AI Analyst Engine",
            severity="Info",
            confidence="Medium",
            status="Advisory",
            endpoint="Collected findings",
            where_found="AI Finding Review Engine",
            how_detected=["One or more configured AI providers reviewed redacted finding evidence"],
            why_risky="This is not a vulnerability. AI review helps prioritize findings, reduce false positives, and improve report quality.",
            evidence={
                "providers": providers,
                "reviewed_findings": len(target_findings),
                "successful_reviews": sum(1 for item in reviews if item.get("ok")),
            },
            recommended_validation=["Treat AI output as advisory and manually validate every security finding."],
            remediation=["No remediation required. Keep API keys in local ignored files or environment variables only."],
        )
    )


def _configured_providers() -> list[str]:
    import os

    load_local_ai_env()
    configured = []
    if os.getenv("OPENAI_API_KEY"):
        configured.append("openai")
    if os.getenv("GEMINI_API_KEY"):
        configured.append("gemini")
    if os.getenv("GROQ_API_KEY"):
        configured.append("groq")
    if os.getenv("OPENROUTER_API_KEY"):
        configured.append("openrouter")
    return configured


def _build_compact_review_payload(findings: list[Finding], metadata: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "findings": [asdict(finding) for finding in findings],
        "selected_metadata": {
            "ip_route_intelligence": metadata.get("ip_route_intelligence"),
            "api_surface_mapper": metadata.get("api_surface_mapper"),
            "access_control_hints": metadata.get("access_control_hints"),
            "xss_precision": metadata.get("xss_precision"),
            "sqli_signal_analysis": metadata.get("sqli_signal_analysis"),
            "exposure_finder": metadata.get("exposure_finder"),
            "correlation": metadata.get("correlation"),
        },
    }
    return redact_secrets(payload)


def _build_prompt(payload: dict[str, Any]) -> str:
    return f"""
{build_ai_safety_instruction()}

Review the following VulnScope-Kali evidence and return JSON with this schema:
{{
  "overall_assessment": "string",
  "highest_value_findings": [
    {{
      "finding_id": "string",
      "verdict": "high_value_manual_review | weak_signal | likely_false_positive | report_ready_after_manual_validation",
      "reason": "string",
      "next_safe_steps": ["string"],
      "report_ready": false
    }}
  ],
  "false_positive_risks": ["string"],
  "missing_evidence": ["string"],
  "recommended_next_modules": ["string"]
}}

Evidence:
{json.dumps(payload, ensure_ascii=False, indent=2)[:24000]}
""".strip()


def _safe_text(text: str) -> str:
    text = text.strip()
    return text[:8000] if text else "{}"


def review_evidence_file(evidence_path: str, providers: list[str] | None = None) -> dict[str, Any]:
    load_local_ai_env()
    path = Path(evidence_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    redacted = redact_secrets(data)
    prompt = _build_prompt(redacted)
    client = AIProviderClient()
    providers = providers or _configured_providers()
    return {provider: asdict(client.call(provider, prompt)) for provider in providers}
