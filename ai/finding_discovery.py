from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from ai.ai_guardrails import build_ai_safety_instruction, redact_secrets
from ai.local_env import load_local_ai_env
from ai.provider_clients import AIProviderClient
from core.evidence_store import EvidenceStore, Finding


DISCOVERY_PROMPT = """
You are the AI Discovery Engine inside VulnScope-Kali.
Your job is to inspect redacted scanner evidence and suggest additional potential findings that rule-based modules may have missed.

Hard rules:
- Authorized testing only.
- Do not generate exploit payloads.
- Do not provide brute-force, bypass, credential capture, database dumping, or destructive steps.
- Do not mark anything as confirmed vulnerability unless explicit proof exists in the evidence.
- Missing headers, API discovery, robots/sitemap discovery, and public config keys are not confirmed vulnerabilities.
- IDOR/BOLA requires two-account private-data proof.
- CORS requires credentialed sensitive-data proof.
- Source maps require sensitive source or secret proof for high reportability.
- Return compact JSON only.

Return this JSON schema:
{
  "discovered_findings": [
    {
      "title": "string",
      "category": "string",
      "affected_endpoint": "string",
      "parameter": "string or null",
      "status": "DISCOVERED | HYPOTHESIS | NEEDS_MANUAL_VALIDATION | FALSE_POSITIVE_LIKELY | CONFIRMED_OBSERVATION | NOT_REPORTABLE",
      "severity": "Info | Low | Medium | High",
      "confidence": "Low | Medium | High",
      "why_it_may_matter": "string",
      "evidence_seen": ["string"],
      "safe_validation_steps": ["string"],
      "required_proof": ["string"],
      "false_positive_risks": ["string"]
    }
  ],
  "high_value_paths_to_review": ["string"],
  "missed_methodologies": ["string"],
  "do_not_report_yet": ["string"]
}
""".strip()


def run_ai_finding_discovery(
    store: EvidenceStore,
    providers: list[str] | None = None,
    max_findings_to_add: int = 10,
) -> None:
    load_local_ai_env()
    providers = providers or _configured_providers()
    if not providers:
        store.metadata["ai_discovery"] = {
            "enabled": False,
            "reason": "No AI providers configured. Run: python3 vulnscope.py --setup-ai-keys",
        }
        return

    payload = _build_discovery_payload(store)
    prompt = _build_prompt(payload)
    client = AIProviderClient()
    provider_results: list[dict[str, Any]] = []
    added = 0

    for provider in providers:
        result = client.call(provider, prompt)
        parsed = _parse_json_safely(result.text)
        provider_results.append(
            {
                "provider": provider,
                "ok": result.ok,
                "error": result.error,
                "parsed": parsed,
                "raw_text": result.text[:6000] if result.text else "{}",
            }
        )
        if not result.ok or not isinstance(parsed, dict):
            continue
        for item in parsed.get("discovered_findings", [])[:max_findings_to_add]:
            if not isinstance(item, dict):
                continue
            finding = _convert_ai_item_to_finding(store, item, provider)
            if finding:
                store.add_finding(finding)
                added += 1

    store.metadata["ai_discovery"] = {
        "enabled": True,
        "providers": providers,
        "added_findings": added,
        "provider_results": redact_secrets(provider_results),
        "safety_note": "AI-discovered findings are hypotheses or observations unless explicit evidence proves otherwise.",
    }


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


def _build_discovery_payload(store: EvidenceStore) -> dict[str, Any]:
    endpoints = sorted(list(store.endpoints))[:300]
    params = {endpoint: values for endpoint, values in list(store.parameters.items())[:120]}
    findings = [asdict(finding) for finding in store.findings[:80]]
    selected_metadata = {
        "root_probe": store.metadata.get("root_probe"),
        "ip_route_intelligence": store.metadata.get("ip_route_intelligence"),
        "api_surface_mapper": store.metadata.get("api_surface_mapper"),
        "deep_route_intelligence": store.metadata.get("deep_route_intelligence"),
        "access_control_hints": store.metadata.get("access_control_hints"),
        "xss_precision": store.metadata.get("xss_precision"),
        "sqli_signal_analysis": store.metadata.get("sqli_signal_analysis"),
        "exposure_finder": store.metadata.get("exposure_finder"),
        "correlation": store.metadata.get("correlation"),
    }
    return redact_secrets(
        {
            "endpoints": endpoints,
            "parameters": params,
            "existing_findings": findings,
            "metadata": selected_metadata,
        }
    )


def _build_prompt(payload: dict[str, Any]) -> str:
    return f"""
{build_ai_safety_instruction()}

{DISCOVERY_PROMPT}

Evidence to analyze:
{json.dumps(payload, indent=2, ensure_ascii=False)[:26000]}
""".strip()


def _parse_json_safely(text: str) -> Any:
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.replace("json\n", "", 1).replace("JSON\n", "", 1).strip()
    try:
        return json.loads(cleaned)
    except Exception:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(cleaned[start : end + 1])
            except Exception:
                return None
    return None


def _convert_ai_item_to_finding(store: EvidenceStore, item: dict[str, Any], provider: str) -> Finding | None:
    title = str(item.get("title") or "AI-Discovered Review Candidate")[:160]
    category = str(item.get("category") or "AI Discovery")[:80]
    endpoint = str(item.get("affected_endpoint") or "Multiple endpoints")[:300]
    status = _safe_status(str(item.get("status") or "NEEDS_MANUAL_VALIDATION"))
    severity = _safe_severity(str(item.get("severity") or "Info"))
    confidence = _safe_confidence(str(item.get("confidence") or "Medium"))

    if status == "CONFIRMED_VULNERABILITY":
        status = "Manual Validation Required"
    else:
        status = status.replace("_", " ").title()

    return Finding(
        finding_id=store.next_finding_id(),
        title=f"AI Discovery: {title}",
        category=category,
        severity=severity,
        confidence=confidence,
        status=status,
        endpoint=endpoint,
        parameter=item.get("parameter") if item.get("parameter") not in {"", None, "null"} else None,
        where_found=f"AI Discovery Engine via {provider}",
        how_detected=[str(x)[:300] for x in item.get("evidence_seen", [])[:8]] or ["AI model reviewed redacted scanner evidence and proposed a manual-review candidate"],
        why_risky=str(item.get("why_it_may_matter") or "AI identified this as a potential review candidate. Manual validation is required.")[:1200],
        evidence={
            "provider": provider,
            "ai_status": item.get("status"),
            "false_positive_risks": item.get("false_positive_risks", []),
            "raw_ai_item": redact_secrets(item),
        },
        recommended_validation=[str(x)[:300] for x in item.get("safe_validation_steps", [])[:10]] or ["Manually validate inside authorized scope."],
        remediation=["Do not report until required proof is collected."] + [str(x)[:300] for x in item.get("required_proof", [])[:8]],
    )


def _safe_status(value: str) -> str:
    allowed = {
        "DISCOVERED",
        "HYPOTHESIS",
        "NEEDS_MANUAL_VALIDATION",
        "FALSE_POSITIVE_LIKELY",
        "CONFIRMED_OBSERVATION",
        "NOT_REPORTABLE",
    }
    value = value.strip().upper()
    return value if value in allowed else "NEEDS_MANUAL_VALIDATION"


def _safe_severity(value: str) -> str:
    value = value.strip().title()
    return value if value in {"Info", "Low", "Medium", "High"} else "Info"


def _safe_confidence(value: str) -> str:
    value = value.strip().title()
    return value if value in {"Low", "Medium", "High"} else "Medium"
