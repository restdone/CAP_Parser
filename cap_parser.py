import json

def load_policies(file_path: str):
    """Load Conditional Access policies from a JSON file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data.get("value", [])

def summarize_policy(policy: dict):
    """Extract key information from a Conditional Access policy."""
    name = policy.get("displayName", "Unknown")
    state = policy.get("state", "unknown")

    conditions = policy.get("conditions", {}) or {}
    users = conditions.get("users", {}) or {}
    apps = conditions.get("applications", {}) or {}
    grant_controls = policy.get("grantControls", {}) or {}
    session_controls = policy.get("sessionControls", {}) or {}

    built_in_controls = grant_controls.get("builtInControls", [])
    custom_controls = grant_controls.get("customAuthenticationFactors", [])

    return {
        "Name": name,
        "State": state,
        "Included Users": users.get("includeUsers", []),
        "Excluded Users": users.get("excludeUsers", []),
        "Included Groups": users.get("includeGroups", []),
        "Included Applications": apps.get("includeApplications", []),
        "Excluded Applications": apps.get("excludeApplications", []),
        "Grant Controls": built_in_controls + custom_controls,
        "Session Controls": list(session_controls.keys()) if session_controls else [],
    }

def is_mfa_policy(policy_summary):
    """Check whether a policy enforces MFA."""
    grants = policy_summary.get("Grant Controls", [])
    return any("mfa" in str(g).lower() or "multifactor" in str(g).lower() for g in grants)

def print_summary(policies):
    """Print all policies and flag MFA exclusions."""
    for i, policy in enumerate(policies, start=1):
        summary = summarize_policy(policy)
        print(f"\nPolicy {i}: {summary['Name']}")
        print(f"  State: {summary['State']}")
        print(f"  Included Users: {summary['Included Users']}")
        print(f"  Excluded Users: {summary['Excluded Users']}")
        print(f"  Included Groups: {summary['Included Groups']}")
        print(f"  Included Applications: {summary['Included Applications']}")
        print(f"  Excluded Applications: {summary['Excluded Applications']}")
        print(f"  Grant Controls: {summary['Grant Controls']}")
        print(f"  Session Controls: {summary['Session Controls']}")

        # 🛑 Check for MFA-related policies and exclusions
        if is_mfa_policy(summary):
            excluded_users = summary.get("Excluded Users", [])
            excluded_groups = summary.get("Included Groups", [])
            if excluded_users or excluded_groups:
                print("  ⚠️  MFA Policy Exclusions Detected:")
                if excluded_users:
                    print(f"     - Excluded Users: {excluded_users}")
                if excluded_groups:
                    print(f"     - Excluded Groups: {excluded_groups}")
            else:
                print("  ✅ No MFA exclusions detected.")

def find_mfa_exclusions(policies):
    """Return a structured list of MFA policies with exclusions."""
    excluded = []
    for policy in policies:
        summary = summarize_policy(policy)
        if is_mfa_policy(summary):
            users = summary.get("Excluded Users", [])
            groups = summary.get("Included Groups", [])
            if users or groups:
                excluded.append({
                    "Policy": summary["Name"],
                    "Excluded Users": users,
                    "Excluded Groups": groups
                })
    return excluded

if __name__ == "__main__":
    policies = load_policies("CAP_resolved.json")
    print(f"Loaded {len(policies)} Conditional Access policies.")

    print_summary(policies)

    # 🧾 Summary of all MFA exclusions
    mfa_exclusions = find_mfa_exclusions(policies)
    if mfa_exclusions:
        print("\n=== MFA Exclusion Summary ===")
        for e in mfa_exclusions:
            print(f"\nPolicy: {e['Policy']}")
            if e['Excluded Users']:
                print(f"  Excluded Users: {e['Excluded Users']}")
            if e['Excluded Groups']:
                print(f"  Excluded Groups: {e['Excluded Groups']}")
    else:
        print("\n✅ No MFA exclusions found in any policy.")
