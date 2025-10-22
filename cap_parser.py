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
    locations = conditions.get("locations", {}) or {}
    device_platforms = conditions.get("devicePlatforms", {}) or {}
    user_risk = conditions.get("userRiskLevels", [])
    signin_risk = conditions.get("signInRiskLevels", [])

    grant_controls = policy.get("grantControls", {}) or {}
    session_controls = policy.get("sessionControls", {}) or {}

    built_in_controls = grant_controls.get("builtInControls", [])
    custom_controls = grant_controls.get("customAuthenticationFactors", [])
    operator = grant_controls.get("operator", "AND")  # Default is AND

    return {
        "Name": name,
        "State": state,
        "Included Users": users.get("includeUsers", []),
        "Excluded Users": users.get("excludeUsers", []),
        "Included Groups": users.get("includeGroups", []),
        "Included Applications": apps.get("includeApplications", []),
        "Excluded Applications": apps.get("excludeApplications", []),
        "Grant Controls": built_in_controls + custom_controls,
        "Grant Operator": operator,
        "Session Controls": list(session_controls.keys()) if session_controls else [],
        "User Risk Levels": user_risk,
        "Sign-in Risk Levels": signin_risk,
        "Device Platforms": {
            "include": device_platforms.get("includePlatforms", []),
            "exclude": device_platforms.get("excludePlatforms", [])
        },
        "Locations": {
            "include": locations.get("includeLocations", []),
            "exclude": locations.get("excludeLocations", [])
        }
    }

def is_mfa_policy(summary):
    """Detect policies enforcing MFA."""
    grants = summary.get("Grant Controls", [])
    return any("mfa" in str(g).lower() or "multifactor" in str(g).lower() for g in grants)

def print_summary(policies):
    """Print policies and flag security-relevant conditions."""
    for i, policy in enumerate(policies, start=1):
        summary = summarize_policy(policy)
        print(f"\nPolicy {i}: {summary['Name']}")
        print(f"  State: {summary['State']}")
        print(f"  Grant Controls: {summary['Grant Controls']}")
        print(f"  Grant Operator: {summary['Grant Operator']}")
        print(f"  Session Controls: {summary['Session Controls']}")

        # --- MFA Enforcement
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
                print("  ✅ MFA required for all targeted identities.")

        # --- Risk-based Conditions
        if summary["User Risk Levels"]:
            print(f"  ⚠️  Applies User Risk Levels: {summary['User Risk Levels']}")
        if summary["Sign-in Risk Levels"]:
            print(f"  ⚠️  Applies Sign-in Risk Levels: {summary['Sign-in Risk Levels']}")

        # --- Device Platform Filtering
        include_plat = summary["Device Platforms"]["include"]
        exclude_plat = summary["Device Platforms"]["exclude"]
        if include_plat and include_plat != ["all"]:
            print(f"  ⚠️  Restricted to Device Platforms: {include_plat}")
        if exclude_plat:
            print(f"  ⚠️  Excluded Device Platforms: {exclude_plat}")

        # --- Location-based Conditions
        include_loc = summary["Locations"]["include"]
        exclude_loc = summary["Locations"]["exclude"]
        if include_loc and include_loc != ["all"]:
            print(f"  ⚠️  Restricted to Locations: {include_loc}")
        if exclude_loc:
            print(f"  ⚠️  Excluded Locations: {exclude_loc}")

        # --- Grant Operator OR
        if summary.get("Grant Operator") == "OR":
            print(f"  ⚠️  Grant Controls operator is OR, builtInControls: {summary['Grant Controls']}")

def generate_security_flags(policies):
    """Return a structured list of security-relevant conditions."""
    findings = []
    for policy in policies:
        summary = summarize_policy(policy)
        issues = []

        # MFA exclusions
        if is_mfa_policy(summary):
            excluded = summary.get("Excluded Users", []) + summary.get("Included Groups", [])
            if excluded:
                issues.append(f"Excludes identities from MFA: {excluded}")

        # Risk levels
        if summary["User Risk Levels"]:
            issues.append(f"Applies User Risk Levels: {summary['User Risk Levels']}")
        if summary["Sign-in Risk Levels"]:
            issues.append(f"Applies Sign-in Risk Levels: {summary['Sign-in Risk Levels']}")

        # Device platforms
        if summary["Device Platforms"]["include"] and summary["Device Platforms"]["include"] != ["all"]:
            issues.append(f"Restricted to Device Platforms: {summary['Device Platforms']['include']}")
        if summary["Device Platforms"]["exclude"]:
            issues.append(f"Excluded Device Platforms: {summary['Device Platforms']['exclude']}")

        # Locations
        if summary["Locations"]["include"] and summary["Locations"]["include"] != ["all"]:
            issues.append(f"Restricted to Locations: {summary['Locations']['include']}")
        if summary["Locations"]["exclude"]:
            issues.append(f"Excluded Locations: {summary['Locations']['exclude']}")

        # Grant Controls operator
        if summary.get("Grant Operator") == "OR":
            issues.append(f"Grant Controls operator is OR, builtInControls: {summary['Grant Controls']}")

        if issues:
            findings.append({
                "Policy": summary["Name"],
                "State": summary["State"],
                "Security Concerns": issues
            })
    return findings

if __name__ == "__main__":
    policies = load_policies("CAP_resolved.json")
    print(f"Loaded {len(policies)} Conditional Access policies.\n")

    print_summary(policies)

    # --- Generate structured security summary
    findings = generate_security_flags(policies)
    if findings:
        print("\n=== Security Concern Summary ===")
        for f in findings:
            print(f"\nPolicy: {f['Policy']} (State: {f['State']})")
            for issue in f["Security Concerns"]:
                print(f"  - {issue}")
    else:
        print("\n✅ No risky or condition-limited policies detected.")
