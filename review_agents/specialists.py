from __future__ import annotations

import re
from urllib.parse import urlparse

from review_agents.base_agent import AgentResult, BaseReviewAgent, collect_urls


class ReconReviewAgent(BaseReviewAgent):
    name = "ReconReviewAgent"

    def run(self, evidence: dict) -> AgentResult:
        subdomains = evidence.get("subdomains", []) if isinstance(evidence, dict) else []
        urls = collect_urls(evidence)
        candidates = []
        if subdomains:
            candidates.append({"type": "subdomain_surface", "count": len(subdomains), "status": "DISCOVERED"})
        if urls:
            hosts = sorted({urlparse(url).netloc for url in urls if urlparse(url).netloc})
            candidates.append({"type": "archived_url_surface", "url_count": len(urls), "host_count": len(hosts), "status": "DISCOVERED"})
        return AgentResult(self.name, candidates=candidates, confidence=0.7, manual_validation_required=False, notes=["Passive recon summary only."])


class AppProfileAgent(BaseReviewAgent):
    name = "AppProfileAgent"

    def run(self, evidence: dict) -> AgentResult:
        urls = collect_urls(evidence)
        signals = {"api": 0, "auth": 0, "admin": 0, "js": 0, "object_routes": 0}
        for url in urls:
            low = url.lower()
            signals["api"] += int("/api/" in low or "graphql" in low)
            signals["auth"] += int(any(x in low for x in ["login", "oauth", "sso", "session", "callback"]))
            signals["admin"] += int(any(x in low for x in ["admin", "dashboard", "console", "manage"]))
            signals["js"] += int(low.endswith(".js") or ".js?" in low or low.endswith(".map"))
            signals["object_routes"] += int(any(x in low for x in ["order", "account", "invoice", "booking", "ticket", "profile", "user"]))
        candidates = [{"type": "app_profile_signal", "signal": k, "count": v} for k, v in signals.items() if v]
        return AgentResult(self.name, candidates=candidates, confidence=0.65, notes=["App profile is inferred from URL and artifact patterns."])


class APIReviewAgent(BaseReviewAgent):
    name = "APIReviewAgent"

    def run(self, evidence: dict) -> AgentResult:
        urls = collect_urls(evidence)
        api_urls = [url for url in urls if re.search(r"/api/|/graphql|/v[0-9]+/", url, re.I)]
        candidates = [{"type": "api_endpoint_candidate", "url": url, "status": "REVIEW_CANDIDATE"} for url in api_urls[:200]]
        actions = []
        if api_urls:
            actions.append({"action": "map_methods_and_auth_context", "reason": "API routes need method, auth, and object-boundary review.", "requires_approval": False})
        return AgentResult(self.name, candidates=candidates, next_actions=actions, confidence=0.72)


class AuthReviewAgent(BaseReviewAgent):
    name = "AuthReviewAgent"

    def run(self, evidence: dict) -> AgentResult:
        urls = collect_urls(evidence)
        auth_urls = [url for url in urls if re.search(r"login|oauth|sso|callback|token|session|logout", url, re.I)]
        candidates = [{"type": "auth_flow_candidate", "url": url, "status": "REVIEW_CANDIDATE"} for url in auth_urls[:150]]
        actions = []
        if auth_urls:
            actions.append({"action": "use_auth_mode_with_owned_accounts", "reason": "Authenticated review is needed for access-control and session posture.", "requires_approval": True})
        return AgentResult(self.name, candidates=candidates, next_actions=actions, confidence=0.68)


class IDORBOLAReviewAgent(BaseReviewAgent):
    name = "IDORBOLAReviewAgent"

    def run(self, evidence: dict) -> AgentResult:
        urls = collect_urls(evidence)
        id_urls = [url for url in urls if re.search(r"[?&](id|user_id|account_id|order_id|invoice_id|uid)=|/(order|account|user|invoice|booking|ticket)s?/", url, re.I)]
        candidates = [{"type": "object_access_candidate", "url": url, "status": "NEEDS_TWO_ACCOUNT_VALIDATION"} for url in id_urls[:200]]
        return AgentResult(self.name, candidates=candidates, next_actions=[{"action": "compare_owned_accounts", "reason": "Object access candidates require Account A/Account B proof.", "requires_approval": True}] if id_urls else [], confidence=0.7)


class JSIntelReviewAgent(BaseReviewAgent):
    name = "JSIntelReviewAgent"

    def run(self, evidence: dict) -> AgentResult:
        urls = collect_urls(evidence)
        js_urls = [url for url in urls if re.search(r"\.(js|map)(\?|$)", url, re.I)]
        candidates = [{"type": "javascript_asset_candidate", "url": url, "status": "REVIEW_CANDIDATE"} for url in js_urls[:200]]
        return AgentResult(self.name, candidates=candidates, confidence=0.66, notes=["JS findings need endpoint extraction and secret false-positive review."])


class ValidationReviewAgent(BaseReviewAgent):
    name = "ValidationReviewAgent"

    def run(self, evidence: dict) -> AgentResult:
        findings = evidence.get("findings", []) if isinstance(evidence, dict) else []
        candidates = []
        for finding in findings[:200] if isinstance(findings, list) else []:
            title = finding.get("title", "finding") if isinstance(finding, dict) else str(finding)
            candidates.append({"type": "validation_task", "title": title, "status": "NEEDS_EVIDENCE_REVIEW", "rule": "No evidence = no confirmed vulnerability"})
        return AgentResult(self.name, candidates=candidates, confidence=0.8, notes=["Validation agent prioritizes proof quality over quantity."])


SPECIALIST_AGENTS = [ReconReviewAgent(), AppProfileAgent(), APIReviewAgent(), AuthReviewAgent(), IDORBOLAReviewAgent(), JSIntelReviewAgent(), ValidationReviewAgent()]
