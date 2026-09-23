# Deterministic Finding Promotion

An LLM never directly creates a finding.

A candidate may be promoted only when all required predicates evaluate true:

- scope_confirmed
- affected_asset_confirmed
- exact behavior reproduced
- independent validator reproduced it
- control comparison completed
- request evidence stored
- response evidence stored
- relevant state/session context stored
- security impact demonstrated
- no unresolved contradictory evidence

Immediate rejection:
- scanner-only claim
- model-only claim
- theoretical-only claim
- out-of-scope behavior
- non-reproducible anomaly

User-facing finding states are only:
- VALIDATING
- VERIFIED

Do not show "possible", "likely", "potential", or "suspected" as findings.