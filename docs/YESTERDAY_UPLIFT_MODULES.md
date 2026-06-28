# Yesterday Uplift Modules

This upgrade adds the remaining high-impact modules discussed for taking VulnScope-Kali beyond a scanner into an evidence-first security analysis workflow.

## Added CLI

```bash
python3 mythic_uplift_cli.py --input scanner-output.txt
```

Short text test:

```bash
python3 mythic_uplift_cli.py --text '/api/orders/123/cancel'
```

Outputs:

```text
reports/output/uplift/
├── uplift-report.md
├── uplift-evidence.json
└── defensive-exports.txt
```

## Added Modules

Implemented in:

```text
mythic_hunter/uplift_modules.py
```

Capabilities:

- HAR-style request/response import
- Burp-style text import through generic parser
- Postman collection import
- OpenAPI/Swagger path analyzer
- Endpoint and parameter extraction
- ObjectFlow mapper
- State-changing action detector
- GraphQL operation and object-field analyzer
- JWT/session posture parser
- Cookie posture review
- Cloud exposure intelligence
- CDN/cache behavior review
- Mobile/API recon from APK/static/Postman-style text
- Report quality gate
- Defensive Splunk SPL export
- Sigma-style review rule export

## Safety Model

The uplift modules do not make network requests. They do not brute force, bypass authentication, access private resources, or use tokens. They only analyze text or files supplied by the user.

Core rule:

```text
No evidence = no confirmed vulnerability.
```

## Best Inputs

Use any of these:

- VulnScope report output
- Burp request/response text
- HAR JSON
- OpenAPI JSON
- Postman collection JSON
- JavaScript snippets
- Endpoint lists
- API responses
- HTTP headers
- Mobile API/static output

## Practical Use

1. Run VulnScope scan.
2. Feed `reports/output/evidence.json` or scanner text into Mythic Hunter.
3. Feed Burp/HAR/OpenAPI/Postman/mobile output into the uplift CLI.
4. Review the generated report quality gate.
5. Only create reports where proof is complete.
