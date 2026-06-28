from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_core.providers.provider_manager import safe_chat

OUT_DIR = Path("reports/output/agent_core/model-council")

DEFAULT_COUNCIL = ["anthropic", "deepseek", "mistral", "fireworks", "cohere", "openrouter", "ollama"]


def run_model_council(prompt: str, providers: list[str] | None = None, max_chars: int = 12000) -> dict[str, Any]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    providers = providers or DEFAULT_COUNCIL
    compact_prompt = prompt[:max_chars]
    results = []
    for provider in providers:
        response = safe_chat(
            compact_prompt,
            provider_name=provider,
            task_type="deep_review",
            system="You are one reviewer in a safe authorized-assessment model council. Return concise, evidence-first guidance only.",
        )
        result = {
            "provider": response.provider,
            "model": response.model,
            "ok": response.ok,
            "content": response.content,
            "error": response.error,
        }
        results.append(result)
        (OUT_DIR / f"{provider}-review.md").write_text(response.content or response.error or "", encoding="utf-8")
    consensus_prompt = _consensus_prompt(results)
    consensus = safe_chat(
        consensus_prompt,
        provider_name="anthropic",
        task_type="deep_review",
        system="You are the final judge. Merge model opinions into practical, safe, evidence-first next steps.",
    )
    output = {"providers": providers, "reviews": results, "consensus": {"ok": consensus.ok, "provider": consensus.provider, "model": consensus.model, "content": consensus.content, "error": consensus.error}}
    (OUT_DIR / "council-summary.json").write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT_DIR / "council-consensus.md").write_text(consensus.content or consensus.error or "", encoding="utf-8")
    return output


def _consensus_prompt(results: list[dict[str, Any]]) -> str:
    compact = []
    for item in results:
        compact.append({"provider": item.get("provider"), "model": item.get("model"), "ok": item.get("ok"), "content": (item.get("content") or item.get("error") or "")[:2500]})
    return (
        "Combine the following model reviews into one VulnScope council consensus. "
        "Return sections: Top Priorities, False Positive Risks, Evidence Needed, Safe Next Steps, Reportability Notes. "
        "Do not suggest destructive or unauthorized actions.\n\n"
        + json.dumps(compact, indent=2, ensure_ascii=False)
    )
