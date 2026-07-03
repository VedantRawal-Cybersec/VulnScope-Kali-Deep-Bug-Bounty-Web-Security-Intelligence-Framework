# VulnScope Dynamic Tool Development

VulnScope supports dynamic, manifest-based tool registration. A tool can live in any GitHub repository and be registered without editing VulnScope core code.

The dynamic system is intentionally approval-gated:

- cloning a repository does not automatically execute it;
- install commands require explicit approval;
- run commands require explicit approval and the tool must be enabled;
- tools are launched with tokenized commands, not raw shell strings;
- stdout/stderr are captured as evidence artifacts.

## Repository layout

A supported tool repository should include one of:

```text
tool.yaml
tool.yml
tool.json
```

Recommended layout:

```text
my-tool/
├── tool.yaml
├── requirements.txt
└── scanner.py
```

## Manifest schema

```yaml
name: Example Scanner
version: "1.0.0"
phase: discovery
install:
  - "python3 -m pip install -r requirements.txt"
run: "python3 scanner.py --target {target} --format {output_format}"
arguments:
  - name: target
    description: Target URL supplied by VulnScope
    required: true
  - name: output_format
    description: Output format requested by VulnScope
    required: false
    default: json
output_parser: json
```

## Supported phases

```text
recon
discovery
validation
exploitation
reporting
```

`exploitation` phase tools are treated as lab-mode tools by the router. They must be approved before they can run.

## Supported output parsers

```text
json
jsonl
plain
```

## Template variables

The `run` command may use:

```text
{target}
{parameter}
{output_format}
{tool_dir}
```

Example:

```yaml
run: "python3 scanner.py --target {target} --output-format {output_format}"
```

## Add a tool

```bash
python3 vulnscope.py --add-tool https://github.com/example/my-tool
```

This clones the repository into `tools/` and creates or updates `tools/registry.json`.

If the repo has no manifest, VulnScope attempts to infer a basic profile from common files:

```text
requirements.txt
pyproject.toml
setup.py
go.mod
package.json
main.py
scanner.py
scan.py
app.py
```

If no run command can be inferred, edit the tool's `tool.yaml` / `tool.json` or `tools/registry.json` after review.

## List tools

```bash
python3 vulnscope.py --list-tools
```

## Approve a tool after review

```bash
python3 vulnscope.py \
  --approve-tool example_scanner_ab12cd34 \
  --approve-tool-run \
  --enable-tool
```

Approve installation separately only after reviewing the repository and install commands:

```bash
python3 vulnscope.py \
  --approve-tool example_scanner_ab12cd34 \
  --approve-tool-install
```

## Run with registered dynamic tools

Registered dynamic tools are loaded into `ToolRouter` from:

```text
tools/registry.json
```

Only tools that are all of the following are considered runnable:

```text
enabled = true
approved_for_run = true
has a run command
phase matches current scheduler phase
```

During a scan, the dynamic phase scheduler writes:

```text
reports/output/cai-superior/<host>/dynamic-tool-phase-summary.json
reports/output/dynamic-tools/*.stdout.txt
reports/output/dynamic-tools/*.stderr.txt
```

Disable dynamic tool scheduling during a scan:

```bash
python3 vulnscope.py --target https://example.com --yes --no-dynamic-tools
```

## Security rules for tool authors

Tools should:

- respect the supplied target scope;
- support JSON or JSONL output when possible;
- provide clear severity/confidence fields;
- avoid destructive behavior;
- avoid credential collection;
- avoid service-disruptive testing;
- make all active behavior explicit in the manifest and documentation.

## Minimal Python example

```python
#!/usr/bin/env python3
import argparse
import json
import time

parser = argparse.ArgumentParser()
parser.add_argument("--target", required=True)
parser.add_argument("--format", default="json")
args = parser.parse_args()

print(json.dumps({
    "tool": "Example Scanner",
    "target": args.target,
    "generated_at": time.time(),
    "findings": []
}))
```

Manifest:

```yaml
name: Example Scanner
version: "1.0.0"
phase: discovery
install: []
run: "python3 scanner.py --target {target} --format {output_format}"
arguments:
  - name: target
    description: Target URL
    required: true
output_parser: json
```
