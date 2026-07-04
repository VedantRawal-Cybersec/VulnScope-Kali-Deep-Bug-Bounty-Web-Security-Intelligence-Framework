# AI Tool Auto-Configurator

The AI Tool Auto-Configurator lets an operator paste a GitHub security-tool repository URL and have VulnScope analyze, configure, manifest, and register it into the main phase router.

## Design contract

VulnScope does not blindly mark random GitHub tools as working.

A tool becomes `READY` only when it has enough configuration to run through VulnScope's existing scoped scheduler. Otherwise it becomes `REGISTERED_REQUIRES_APPROVAL`, `NEEDS_MANUAL_REVIEW`, or `BLOCKED` with reasons.

## Commands

Analyze only:

```bash
python3 vulnscope.py --ai-analyze-tool https://github.com/owner/repo
```

Analyze, generate manifest, register:

```bash
python3 vulnscope.py --ai-add-tool https://github.com/owner/repo
```

Analyze many tools from file:

```bash
python3 vulnscope.py --ai-add-tool-file tools.txt
```

Approve safe passive/safe-active run only after review:

```bash
python3 vulnscope.py --ai-add-tool https://github.com/owner/repo --ai-tool-approve-run
```

Allow detected install commands:

```bash
python3 vulnscope.py --ai-add-tool https://github.com/owner/repo --ai-tool-install
```

List registered tools:

```bash
python3 vulnscope.py --list-tools
```

## What it analyzes

- README and documentation
- file tree
- Python, Go, Node, Rust, and shell entrypoints
- requirements.txt / pyproject.toml / setup.py
- package.json
- go.mod
- Cargo.toml
- Dockerfile / Makefile / install.sh
- safe `--help`, `-h`, and `--version` probes

## Generated files

For each repo:

```text
tools/<owner>__<repo>/manifest.json
logs/tool_analysis/<repo>_analysis.json
logs/tool_analysis/<repo>_auto_config_result.json
```

Batch mode writes:

```text
logs/tool_analysis/batch_auto_config_summary.json
```

## Status meanings

- `READY`: manifest, run command, registration, and approval are present.
- `REGISTERED_REQUIRES_APPROVAL`: manifest + registry are ready, but run approval is still required.
- `NEEDS_MANUAL_REVIEW`: repo was analyzed, but entrypoint/probe/run configuration is uncertain.
- `BLOCKED`: repo matched blocked behavior indicators.

## Safety boundary

Configuration never runs the tool against a target. It only runs help/version probes. Actual target execution stays inside VulnScope's same-scope scheduler and requires approval.
