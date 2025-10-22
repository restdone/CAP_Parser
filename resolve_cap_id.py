import json
import requests
import subprocess
from time import sleep

GRAPH_URL = "https://graph.microsoft.com/v1.0"

def get_graph_token():
    """Get a Microsoft Graph access token from Azure CLI."""
    result = subprocess.run(
        ["az", "account", "get-access-token", "--resource-type", "ms-graph", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    token_data = json.loads(result.stdout)
    return token_data["accessToken"]

def is_guid(value):
    """Rudimentary check for GUID-like strings."""
    import re
    return bool(re.fullmatch(r"[0-9a-fA-F-]{36}", value))

def resolve_display_name(object_id, token, cache):
    """Resolve any object ID or appId (user, group, servicePrincipal, or application) to a display name."""
    if object_id in cache:
        return cache[object_id]

    headers = {"Authorization": f"Bearer {token}"}

    # --- 1️ Try servicePrincipal by objectId
    resp = requests.get(f"{GRAPH_URL}/servicePrincipals/{object_id}", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        name = data.get("displayName") or data.get("appDisplayName") or object_id
        cache[object_id] = name
        return name

    # --- 2️ Try application by objectId
    resp = requests.get(f"{GRAPH_URL}/applications/{object_id}", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        name = data.get("displayName") or data.get("appDisplayName") or object_id
        cache[object_id] = name
        return name

    # --- 3️ Try user
    resp = requests.get(f"{GRAPH_URL}/users/{object_id}", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        name = data.get("displayName") or data.get("userPrincipalName") or object_id
        cache[object_id] = name
        return name

    # --- 4️ Try group
    resp = requests.get(f"{GRAPH_URL}/groups/{object_id}", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        name = data.get("displayName") or object_id
        cache[object_id] = name
        return name

    # --- 5️ If none of the above, maybe it's an appId, not an objectId
    if is_guid(object_id):
        # Try lookup by appId
        for entity in ["servicePrincipals", "applications"]:
            url = f"{GRAPH_URL}/{entity}?$filter=appId eq '{object_id}'"
            resp = requests.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("value", [])
                if data:
                    name = data[0].get("displayName") or data[0].get("appDisplayName") or object_id
                    cache[object_id] = name
                    return name

    # --- 6️ Fallback to returning the raw ID
    cache[object_id] = object_id
    return object_id

def collect_all_ids(data):
    """Collect all UUIDs or appIds from users, groups, and applications in all policies."""
    ids = set()
    for policy in data.get("value", []):
        cond = policy.get("conditions", {}) or {}
        users = cond.get("users", {}) or {}
        apps = cond.get("applications", {}) or {}

        for key in ["includeUsers", "excludeUsers", "includeGroups"]:
            ids.update(users.get(key, []))
        for key in ["includeApplications", "excludeApplications"]:
            ids.update(apps.get(key, []))

    # Remove keywords like "All" and "None"
    return [i for i in ids if isinstance(i, str) and len(i) > 10]

def replace_ids_with_names(data, mapping):
    """Replace UUIDs/appIds with display names throughout the JSON."""
    for policy in data.get("value", []):
        cond = policy.get("conditions", {}) or {}
        users = cond.get("users", {}) or {}
        apps = cond.get("applications", {}) or {}

        for key in ["includeUsers", "excludeUsers", "includeGroups"]:
            users[key] = [mapping.get(i, i) for i in users.get(key, [])]
        for key in ["includeApplications", "excludeApplications"]:
            apps[key] = [mapping.get(i, i) for i in apps.get(key, [])]
    return data

if __name__ == "__main__":
    # 1️ Load CAP.json
    with open("CAP.json", "r", encoding="utf-8") as f:
        cap_data = json.load(f)

    print("Collecting object IDs and appIds...")
    all_ids = collect_all_ids(cap_data)
    print(f"Found {len(all_ids)} unique IDs to resolve.\n")

    # 2️ Get Graph token
    token = get_graph_token()
    id_name_map = {}

    # 3️ Resolve IDs (with caching)
    for idx, oid in enumerate(all_ids, start=1):
        name = resolve_display_name(oid, token, id_name_map)
        print(f"[{idx}/{len(all_ids)}] {oid} → {name}")
        sleep(0.2)

    # 4️ Replace in JSON and save
    updated_data = replace_ids_with_names(cap_data, id_name_map)
    with open("CAP_resolved.json", "w", encoding="utf-8") as f:
        json.dump(updated_data, f, indent=2)

    print("\n✅ Saved CAP_resolved.json with users, groups, and appId/application names.")
