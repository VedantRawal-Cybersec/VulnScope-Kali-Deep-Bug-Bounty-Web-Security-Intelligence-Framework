# Specialist Agent Contracts

Use narrow, short-lived specialists rather than generic "find bugs" agents.

Roles:
SCOPE_GUARDIAN, APPLICATION_CARTOGRAPHER, ROUTE_ENDPOINT_MAPPER, JAVASCRIPT_ANALYST, API_ANALYST, AUTHENTICATION_ANALYST, SESSION_ANALYST, AUTHORIZATION_ANALYST, SERVER_INPUT_ANALYST, CLIENT_SECURITY_ANALYST, BUSINESS_LOGIC_ANALYST, WORKFLOW_STATE_ANALYST, INFRASTRUCTURE_ANALYST, DIFFERENTIAL_ANALYST, INTELLIGENCE_ANALYST, INDEPENDENT_VALIDATOR, SKEPTIC_REVIEWER, EVIDENCE_ANALYST.

Every job must contain:
job_id, specialist, exact objective, in-scope assets, allowed opaque session refs, known facts, unknowns, duplicate-work exclusions, required outputs, and may_create_finding=false.

Every output must contain:
tests_performed, observations, evidence_ids, new_entities, new_relationships, negative_knowledge, remaining_unknowns, suggested_followups.

Validators get minimum neutral reproduction facts, not the discovering agent's conclusion.

The skeptic attempts benign explanations first: intended behavior, explicit permissions, cache/stale state, proxy/WAF effects, session confusion, race/noise, test artifact, duplicate/root-cause overlap.

Only deterministic promotion code may create a VERIFIED finding.