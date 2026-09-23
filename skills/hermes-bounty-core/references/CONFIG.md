# Configuration Model

Program config should include:
- program name/url
- explicit authorization confirmation
- program-specific prohibited techniques
- human-approval requirements
- opaque session IDs/roles
- Burp bridge endpoint

Scope config:
- exact allowlist
- explicit denylist
- request-rate limit
- in-scope redirect rule
- default decision = deny

Finding policy:
allow_unverified_findings=false
require scope, reproduction, independent validation, control test, request/response evidence, affected asset, impact, no contradictory evidence.

Keep raw cookies/tokens in Burp or a local secret vault; Hermes should see opaque session references only.