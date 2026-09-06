import json
import urllib.request

base = "http://localhost:8000"

def post(path, data, headers=None):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())

def get(path, token):
    req = urllib.request.Request(base + path, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

login = post("/api/v1/auth/login", {"email": "user@example.com", "password": "changeme1"})
token = login["access_token"]
print("login_ok")

inbox = get("/api/v1/mailbox/folders/inbox", token)
print("inbox_count", len(inbox))

# outbound compose to local mailbox (scan + postfix submit)
try:
    detail = post(
        "/api/v1/mailbox/compose",
        {"recipient": "analyst@example.com", "subject": "Internal status", "body": "All systems nominal."},
        headers={"Authorization": f"Bearer {token}"},
    )
    print("compose_decision", detail.get("decision"), "risk", detail.get("fused_risk_score"))
except Exception as e:
    print("compose_err", e)
