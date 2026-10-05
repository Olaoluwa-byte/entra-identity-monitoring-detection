#!/usr/bin/env python3
"""Pull Entra ID sign-in and audit logs via Microsoft Graph to JSON-lines files."""
import json, os, pathlib, sys, datetime as dt
import requests

TENANT = os.environ["ENTRA_TENANT_ID"]
CLIENT = os.environ["ENTRA_CLIENT_ID"]
SECRET = os.environ["ENTRA_CLIENT_SECRET"]
OUT = pathlib.Path(os.environ.get("ENTRA_OUT_DIR", "/var/log/entra"))
STATE = OUT / ".state.json"
ENDPOINTS = {  # name: (graph path, timestamp field)
    "signins": ("auditLogs/signIns", "createdDateTime"),
    "directoryaudits": ("auditLogs/directoryAudits", "activityDateTime"),
}

def get_token():
    r = requests.post(
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
        data={"client_id": CLIENT, "client_secret": SECRET,
              "grant_type": "client_credentials",
              "scope": "https://graph.microsoft.com/.default"},
        timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def pull(name, path, field, token, state):
    since = state.get(name) or (dt.datetime.now(dt.timezone.utc)
            - dt.timedelta(days=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = f"https://graph.microsoft.com/v1.0/{path}"
    params = {"$filter": f"{field} gt {since}", "$top": 500}
    latest, count = since, 0
    with open(OUT / f"{name}.json", "a") as fh:
        while url:
            r = requests.get(url, headers={"Authorization": f"Bearer {token}"},
                             params=params, timeout=60)
            if r.status_code in (401, 403):
                print(f"{name}: {r.status_code} (license or permission): {r.text[:200]}",
                      file=sys.stderr)
                return
            r.raise_for_status()
            body = r.json()
            for ev in body.get("value", []):
                fh.write(json.dumps(ev) + "\n")
                latest = max(latest, ev.get(field, latest))
                count += 1
            url, params = body.get("@odata.nextLink"), None
    state[name] = latest
    print(f"{name}: {count} events, checkpoint {latest}")

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    token = get_token()
    for name, (path, field) in ENDPOINTS.items():
        pull(name, path, field, token, state)
    STATE.write_text(json.dumps(state))

if __name__ == "__main__":
    main()
