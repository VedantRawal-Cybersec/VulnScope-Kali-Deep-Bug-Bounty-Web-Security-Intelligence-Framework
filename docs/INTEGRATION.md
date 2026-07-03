# VulnScope Integration Notes

This document describes how VulnScope integrates native framework logic and external GitHub tools.

## Integration boundary

VulnScope does not copy offensive exploit code from third-party repositories into core modules. Instead, it provides:

- a dynamic manifest-based tool registry;
- a batch installer for GitHub tools listed in `tools.txt`;
- a phase scheduler that runs enabled, approved tools in scan phase order;
- evidence capture for stdout/stderr and parsed JSON/JSONL/plain output;
- dashboard visibility through the ToolRouter matrix;
- scope locking, confirmation prompts, request budgets, and non-destructive core behavior.

Third-party tools remain separate projects under `tools/`. Their authors and licenses remain authoritative for their source code. Before adding a repository, review its license and behavior.

## External tool integration flow

1. Add one GitHub URL per line in `tools.txt`.
2. Run `python3 vulnscope.py --add-tool -tools.txt`.
3. VulnScope clones or updates each repository under `tools/`.
4. VulnScope reads `tool.yaml`, `tool.yml`, or `tool.json` if present.
5. If no manifest exists, VulnScope infers a basic discovery-phase profile from common files.
6. Install commands are logged in `logs/tool_install.log`.
7. Registered tools are saved in `tools/registry.json`.
8. During scans, enabled and approved tools are loaded by ToolRouter and scheduled by phase.

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

VulnScope core does not enable destructive activity, credential attacks, callback injection, cache poisoning, service disruption, or target data modification. Lab mode is intended for owned/local vulnerable labs and still uses VulnScope guardrails unless a separately installed tool performs behavior outside VulnScope core.
