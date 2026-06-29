#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from artemis.config import load_config, write_default
from artemis.orchestrator import ArtemisBrain


def main() -> int:
    parser = argparse.ArgumentParser(description="ARTEMIS passive autonomous vulnerability intelligence")
    parser.add_argument("--config", default="artemis_config.yaml")
    parser.add_argument("--scope-policy", default="scope_policy.yaml")
    parser.add_argument("--init-config", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--forever", action="store_true")
    args = parser.parse_args()
    if args.init_config:
        p = write_default(args.config)
        print(json.dumps({"created": str(p)}, indent=2))
        return 0
    cfg = load_config(args.config)
    brain = ArtemisBrain(config=cfg, scope_policy=args.scope_policy)
    if args.forever:
        brain.run_forever()
        return 0
    result = brain.run_once()
    print(json.dumps({"targets": len(result.get("targets", [])), "report": "reports/output/artemis/run/artemis-run.md"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
