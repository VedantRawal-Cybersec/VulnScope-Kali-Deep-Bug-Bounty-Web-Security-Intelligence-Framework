# Deterministic Finding Promotion

LLMs and scanners never directly create verified findings.

Required predicates:
- scope_confirmed
- affected_asset_confirmed
- exact behavior reproduced
- independent validator reproduced
- control comparison completed
- request evidence stored
- response evidence stored
- relevant state/session context stored
- security impact demonstrated
- no unresolved contradictory evidence

Reject:
- scanner-only
- LLM-only
- theoretical-only
- out-of-scope
- non-reproducible anomaly

User-facing finding states:
VALIDATING
VERIFIED

Do not publish speculative vulnerability labels as findings.