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
    """Check if a string is GUID-like."""
    import re
    return bool(re.fullmatch(r"[0-9a-fA-F-]{36}", value))

def resolve_display_name(object_id, token, cache):
    """Resolve any object ID or appId (user, group, servicePrincipal, application) to display name."""
    if object_id in cache:
        return cache[object_id]

    headers = {"Authorization": f"Bearer {token}"}

    # Try servicePrincipal, application, user, group
    for url in [
        f"{GRAPH_URL}/servicePrincipals/{object_id}",
        f"{GRAPH_URL}/applications/{object_id}",
        f"{GRAPH_URL}/users/{object_id}",
        f"{GRAPH_URL}/groups/{object_id}"
    ]:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            display_name = data.get("displayName") or data.get("appDisplayName") or data.get("userPrincipalName") or object_id
            cache[object_id] = display_name
            return display_name

    # Try appId lookup
    if is_guid(object_id):
        for entity in ["servicePrincipals", "applications"]:
            url = f"{GRAPH_URL}/{entity}?$filter=appId eq '{object_id}'"
            resp = requests.get(url, headers=headers)
            if resp.status_code == 200:
                data_list = resp.json().get("value", [])
                if data_list:
                    display_name = data_list[0].get("displayName") or data_list[0].get("appDisplayName") or object_id
                    cache[object_id] = display_name
                    return display_name

    cache[object_id] = object_id
    return object_id

# --- New Named Location Resolver ---
def get_named_locations(token):
    """Retrieve all Named Locations and map UUIDs to display names."""
    url = f"{GRAPH_URL}/identity/conditionalAccess/namedLocations"
    headers = {"Authorization": f"Bearer {token}"}
    named_locations = {}

    while url:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        for loc in data.get("value", []):
            named_locations[loc["id"]] = loc.get("displayName", loc["id"])
        url = data.get("@odata.nextLink")  # pagination if needed

    return named_locations

def replace_ids_with_names(data, cache, token, named_locations):
    """Replace all object IDs/appIds/users/groups/locations with display names."""
    for policy in data.get("value", []):
        cond = policy.get("conditions", {}) or {}
        users = cond.get("users", {}) or {}
        apps = cond.get("applications", {}) or {}
        locs = cond.get("locations", {}) or {}

        for key in ["includeUsers", "excludeUsers", "includeGroups"]:
            users[key] = [resolve_display_name(i, token, cache) for i in users.get(key, [])]

        for key in ["includeApplications", "excludeApplications"]:
            apps[key] = [resolve_display_name(i, token, cache) for i in apps.get(key, [])]

        for key in ["includeLocations", "excludeLocations"]:
            locs[key] = [named_locations.get(lid, lid) for lid in locs.get(key, [])]

    return data

def collect_all_ids(data):
    """Collect all object IDs and appIds (users, groups, apps)."""
    ids = set()
    for policy in data.get("value", []):
        cond = policy.get("conditions", {}) or {}
        users = cond.get("users", {}) or {}
        apps = cond.get("applications", {}) or {}

        for key in ["includeUsers", "excludeUsers", "includeGroups"]:
            ids.update(users.get(key, []))
        for key in ["includeApplications", "excludeApplications"]:
            ids.update(apps.get(key, []))

    return [i for i in ids if isinstance(i, str) and len(i) > 10]

# --- Main Execution ---
if __name__ == "__main__":
    with open("CAP.json", "r", encoding="utf-8") as f:
        cap_data = json.load(f)

    print("Collecting object/app IDs...")
    all_ids = collect_all_ids(cap_data)
    print(f"Found {len(all_ids)} object/app IDs.\n")

    token = get_graph_token()
    cache = {}

    print("\nResolving object/app IDs...")
    for idx, oid in enumerate(all_ids, start=1):
        name = resolve_display_name(oid, token, cache)
        print(f"[{idx}/{len(all_ids)}] {oid} → {name}")
        sleep(0.1)

    print("\nRetrieving all Named Locations...")
    named_locations = get_named_locations(token)
    print(f"Found {len(named_locations)} named locations.\n")

    print("Replacing IDs and location UUIDs in CAP JSON...")
    updated_data = replace_ids_with_names(cap_data, cache, token, named_locations)

    with open("CAP_resolved.json", "w", encoding="utf-8") as f:
        json.dump(updated_data, f, indent=2)

    print("\n✅ Saved CAP_resolved.json with users, groups, apps, appIds, and named locations resolved.")
