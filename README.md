# CAP_Parser
/// This is a quick and dirty tool to catch obvious mistake in Conditional Access Policy 
<img width="818" height="101" alt="image" src="https://github.com/user-attachments/assets/49e0cfd3-1686-45ec-9341-59025ec4f4fd" />

A tool to make Azure Conditional Access Policer easier to read

Step 1. Get the CAP Json
```
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --output json > CAP.json
```
Step 2. Convert the ids in json to readable
```
python3 resolve_cap_id.py
```
Step 3. Read it
```
python cap_parser.py
```
Under the MFA Exclusion Summary, it wil show what group or user excluded like:
 1. Excluded from Conditional Access Policy (MFA)
 2. Excludeded from location
 3. Excluded from builtIncontrol (using operator OR)
    
