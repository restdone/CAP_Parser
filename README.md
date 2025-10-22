# CAP_Parser
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
Under the MFA Exclusion Summary, it wil show what group or user excluded from MFA
