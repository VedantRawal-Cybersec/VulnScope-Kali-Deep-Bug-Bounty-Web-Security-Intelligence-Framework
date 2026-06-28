# CAI-Inspired Feature Parity Upgrade

This document tracks the CAI-style capabilities implemented in VulnScope.

The goal is not to blindly copy another codebase. The goal is to implement the same class of architecture in a Kali-native, evidence-first, authorized-assessment workflow.

## 1. Broad AI Model Routing

Implemented through:

```text
agent_core/model_router.py
```

Supported direct provider keys:

```text
OPENAI_API_KEY
ANTHROPIC_API_KEY
DEEPSEEK_API_KEY
GEMINI_API_KEY
GROQ_API_KEY
OPENROUTER_API_KEY
MISTRAL_API_KEY
COHERE_API_KEY
TOGETHER_API_KEY
FIREWORKS_API_KEY
PERPLEXITY_API_KEY
```

Local/private routing:

```text
OLLAMA_HOST
OLLAMA_MODEL
```

OpenRouter and Ollama-compatible routing allow broad model coverage while keeping VulnScope's local redaction policy.

## 2. Built-in Security Tool Orchestration

Implemented through:

```text
arsenal/tool_catalog.yaml
agent_core/tool_router.py
agent_core/tool_safety_policy.py
```

Allowed categories:

```text
passive reconnaissance
web validation
authenticated owned-account review
evidence analysis
reporting
learning labs and CTFs where allowed
```

Blocked by default:

```text
credential collection
destructive actions
unauthorized access
persistence
sensitive host changes
payment or purchase actions
```

## 3. Workflow Readiness

Implemented through:

```text
hunt.py
workflow/
agent_core/activity_log.py
reports/output/agent_core/activity.jsonl
reports/output/workflow/*checkpoint.json
```

Recommended validation targets:

```text
local labs
CTFs where allowed
owned applications
bug bounty assets where scope explicitly permits testing
```

## 4. Agent-based Architecture

Implemented modules:

```text
agent_core/
review_agents/
workflow/
recon/
auth/
arsenal/
```

Current specialist agents:

```text
ReconReviewAgent
AppProfileAgent
APIReviewAgent
AuthReviewAgent
IDORBOLAReviewAgent
JSIntelReviewAgent
ValidationReviewAgent
```

## 5. Guardrails Protection

Implemented through:

```text
agent_core/prompt_firewall.py
agent_core/tool_safety_policy.py
agent_core/human_gate.py
core/authorization_guard.py
```

Key rules:

```text
No evidence = no confirmed vulnerability
Credentials stay local
AI receives redacted evidence only
Owned accounts only for authenticated review
Human approval for controlled actions
Blocked sensitive command categories
```

## 6. Research-oriented Design

Implemented through structured artifacts:

```text
reports/output/agent_core/activity.jsonl
reports/output/agent_core/workflow-memory.json
reports/output/agent_core/agent-core-summary.json
reports/output/workflow/reportability-scores.json
reports/output/workflow/validation-tasks.json
```

These artifacts make VulnScope suitable for portfolio demonstrations, research logging, CTF/lab evaluation, and workflow improvement.

## Recommended Command

```bash
python3 hunt.py --target https://example.com --mode bounty --agent-core --yes
```

For comprehensive local review:

```bash
python3 hunt.py --target https://example.com --mode comprehensive --agent-core --yes
```
