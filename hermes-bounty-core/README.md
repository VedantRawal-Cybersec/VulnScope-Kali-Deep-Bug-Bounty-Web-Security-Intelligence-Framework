# Hermes Bounty Core

A Hermes skill + orchestration blueprint for authorized bug bounty work.

## What this adds

- scope-locked target interaction
- persistent Target Brain
- Burp-first HTTP evidence model
- specialist-agent contracts
- workflow/state/object graph reasoning
- coverage-driven scheduling
- negative-knowledge tracking
- independent validation
- deterministic finding-promotion rules
- vulnerability-intelligence ingestion architecture
- clean CLI-oriented event model

## Install as a Hermes skill

Clone this repository, then copy or link:

\`hermes-bounty-core/\`

into your Hermes skills directory.

The main entry point is \`SKILL.md\`.

## Suggested project layout

Use this skill together with a project-local:
- \`.hermes.md\`
- \`AGENTS.md\`
- \`config/program.yaml\`
- \`config/scope.yaml\`
- \`config/policy.yaml\`

## Important

This repository intentionally separates:
- broad read-only Internet research
- active target interaction

Active testing must remain restricted to the exact authorized bounty scope and program rules.

The included MCP documents are contracts/scaffolds. Connect them to your existing Burp integration and local Hermes environment.