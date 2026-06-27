def confirm_authorization(target_url: str) -> bool:
    print("\n┌─────────────────────────────── Authorization ────────────────────────────────┐")
    print("│ VulnScope-Kali is only for authorized testing.                                │")
    print("│ Use it only on assets you own, labs, CTFs, or in-scope bug bounty targets.     │")
    print("│ You are responsible for following the target program policy and laws.          │")
    print("└──────────────────────────────────────────────────────────────────────────────┘")
    print(f"\nTarget: {target_url}")
    answer = input("\n[?] Do you confirm this target is authorized and in scope? yes/no: ").strip().lower()
    return answer in {"yes", "y"}
