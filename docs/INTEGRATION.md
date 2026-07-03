# VulnScope Integration Notes

This document describes how VulnScope integrates native framework logic and external GitHub tools.

## Integration boundary

VulnScope does not copy third-party offensive source code into core modules. Instead, it provides:

- a dynamic manifest-based tool registry;
- a batch installer for GitHub tools listed in `tools.txt` or `config/tools.txt`;
- a phase scheduler that runs enabled and approved tools in scan phase order;
- a native unified research orchestrator that converts public-framework patterns into safe decision profiles;
- evidence capture for stdout/stderr and parsed JSON/JSONL/plain output;
- dashboard visibility through the ToolRouter matrix;
- scope locking, confirmation prompts, request budgets, and guarded core behavior.

Third-party tools remain separate projects under `tools/`. Their authors and licenses remain authoritative for their source code. Before adding a repository, review its license and behavior.

## Native research orchestration

VulnScope includes:

```text
core/engines/research_profiles.py
core/engines/unified_research_orchestrator.py
```

These files model orchestration patterns as decision profiles:

- agentic planning and handoff patterns;
- recon, discovery, validation, and reporting phase sequencing;
- evidence triage and confidence scoring rules;
- dynamic tool delegation preferences;
- expected evidence outputs.

The orchestrator writes:

```text
reports/output/cai-superior/<host>/unified-research-orchestration.json
reports/output/cai-superior/<host>/unified-research-orchestration.md
```

It is a decision layer. It does not embed third-party payload code.

## External tool integration flow

1. Add one GitHub URL per line in `tools.txt` or `config/tools.txt`.
2. Run `python3 vulnscope.py --add-tool -tools.txt`.
3. VulnScope clones or updates each repository under `tools/`.
4. VulnScope reads `tool.yaml`, `tool.yml`, or `tool.json` if present.
5. If no manifest exists, VulnScope infers a basic discovery-phase profile from common files.
6. Install commands are logged in `logs/tool_install.log`.
7. Registered tools are saved in `tools/registry.json`.
8. During scans, enabled and approved tools are loaded by ToolRouter and scheduled by phase.

## Curated profile set

The native profile set covers the requested repository list, including Strix, Raptor, AI-VAPT, HexStrike AI, AutoPentestFramework, CVE-Hunter, DeepSubs, ghsubs, WebStrike, SecuSploitX, Master OSINT Toolkit, and GitFive.

## Credits and licenses

For each third-party repository added through `tools.txt`, keep attribution to the original authors. Do not remove license files from cloned repositories.

Recommended review fields:

```text
Repository:
Authors:
License:
Purpose:
Phase:
Install command:
Run command:
Risk notes:
Approved by:
Date:
```

## Safety defaults

VulnScope core keeps scope, confirmation, request-budget, and reporting guardrails active. Lab mode is intended for owned or intentionally vulnerable labs and remains separate from third-party tool behavior.
