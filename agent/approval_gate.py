from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ApprovalDecision:
    approved: bool
    reason: str


BLOCKED_TERMS = [
    "--os-shell",
    "--passwords",
    "--dump",
    "--dump-all",
    "--risk=3",
    "--level=5",
    "hydra",
    "medusa",
    "john",
    "hashcat",
    "msfconsole",
    "meterpreter",
    "reverse shell",
    "nc -e",
    "rm -rf",
]


def assess_command_safety(command: list[str]) -> ApprovalDecision:
    joined = " ".join(command).lower()
    for term in BLOCKED_TERMS:
        if term in joined:
            return ApprovalDecision(False, f"Blocked unsafe term: {term}")
    if "ffuf" in joined and "-rate" not in joined:
        return ApprovalDecision(False, "ffuf requires explicit rate limiting")
    if "nuclei" in joined and "-rl" not in joined:
        return ApprovalDecision(False, "nuclei requires explicit rate limiting")
    return ApprovalDecision(True, "Command passed safety pre-check")


def ask_user_approval(title: str, command: list[str], risk_level: str, auto_yes: bool = False) -> bool:
    decision = assess_command_safety(command)
    if not decision.approved:
        print(f"[!] Safety gate blocked {title}: {decision.reason}")
        return False
    if auto_yes and risk_level in {"passive", "internal"}:
        return True
    print("\n┌──────────────────────── Approval Required ────────────────────────┐")
    print(f"Tool/Step : {title}")
    print(f"Risk      : {risk_level}")
    print("Command   : " + " ".join(command))
    print("Rule      : Only run this on authorized in-scope targets.")
    print("└───────────────────────────────────────────────────────────────────┘")
    answer = input("Approve this step? yes/no: ").strip().lower()
    return answer in {"yes", "y"}
