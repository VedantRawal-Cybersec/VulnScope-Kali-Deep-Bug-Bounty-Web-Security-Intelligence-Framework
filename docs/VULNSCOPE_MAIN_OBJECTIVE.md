# VulnScope Main Objective

VulnScope's primary objective is to become a practical, autonomous, evidence-first web security analysis assistant for authorized testing and bug-bounty preparation.

## Core direction

The tool must prioritize:

1. **Human-like autonomous reasoning**
   - Use LLMs for planning, prioritization, and evidence interpretation.
   - Keep every LLM decision bounded by deterministic safety guardrails.
   - Avoid shallow one-shot scanning; use a clear observe → decide → act → learn loop.

2. **Reliable parameter testing**
   - Discover parameters from URLs, GET forms, JavaScript routes, metadata, and same-scope redirects.
   - Prioritize high-value parameters first.
   - Progress each parameter through a safe testing sequence instead of repeatedly testing the same input.
   - Produce evidence-backed findings or clear review leads.

3. **Large-scope readiness**
   - Work on large authorized websites without becoming slow or stuck.
   - Use request budgets, adaptive backoff, low-impact canaries, and transparent user-agent behavior.
   - Surface progress through a real-time CLI dashboard.

4. **One clean main workflow**
   - The default path should be the Safe CAI ReAct autonomous engine.
   - Legacy/experimental modules must be opt-in, not automatically run after the main engine.
   - Extra files/modules should not degrade the main workflow.

5. **Safety and authorization**
   - Same-scope only.
   - No credential attacks.
   - No destructive actions.
   - No stealth, WAF bypass, brute force, reverse shells, or production data modification.
   - No exploit payload execution against production systems.

## Current engineering priority

Before adding more modules, fix the core loop:

- Parameter scheduling must not repeat the same test forever.
- LLM calls must not slow down every turn.
- Final reports must show exactly what was tested, skipped, confirmed, or left for review.
- Legacy pipelines must not run by default.
