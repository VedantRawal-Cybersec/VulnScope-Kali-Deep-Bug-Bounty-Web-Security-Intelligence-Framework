# Specialist Agent Contracts

Use narrow, short-lived agents. Never delegate a generic task such as "find vulnerabilities".

## Available roles

1. SCOPE_GUARDIAN
2. APPLICATION_CARTOGRAPHER
3. ROUTE_ENDPOINT_MAPPER
4. JAVASCRIPT_ANALYST
5. API_ANALYST
6. AUTHENTICATION_ANALYST
7. SESSION_ANALYST
8. AUTHORIZATION_ANALYST
9. SERVER_INPUT_ANALYST
10. CLIENT_SECURITY_ANALYST
11. BUSINESS_LOGIC_ANALYST
12. WORKFLOW_STATE_ANALYST
13. INFRASTRUCTURE_ANALYST
14. DIFFERENTIAL_ANALYST
15. INDEPENDENT_VALIDATOR
16. SKEPTIC_REVIEWER
17. EVIDENCE_ANALYST
18. INTELLIGENCE_ANALYST

## Required job envelope

Every delegated job must contain:
- job_id
- specialist
- exact objective
- in-scope assets
- allowed session references
- relevant known facts
- relevant unknowns
- duplicate-work exclusions
- required outputs
- explicit statement: may_create_finding=false

## Required output

- tests_performed
- observations
- evidence_ids
- new_entities
- new_relationships
- negative_knowledge
- remaining_unknowns
- suggested_followups

## Validator rule

Validators receive the minimum facts needed to reproduce behavior. Do not tell them the discovering agent's conclusion.

## Skeptic rule

The skeptic attempts to explain the behavior as:
- intended functionality
- role permission
- cached/stale state
- test artifact
- WAF/proxy behavior
- race/noise
- session confusion
- duplicate/root-cause overlap

Only a deterministic promotion gate may create a verified finding.