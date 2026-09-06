import json, time
from pathlib import Path
import httpx
time.sleep(4)
pdf = Path(r"C:\Users\Suhani Buche\Downloads\IEEE_Conference_Template__1_ (1).pdf")
c = httpx.Client(timeout=120)
print("pdf status", c.get("http://localhost:8000/api/v1/lab/models/status").json()["pdf"])
with pdf.open("rb") as fh:
    r = c.post("http://localhost:8000/api/v1/lab/scan/pdf", files={"file": (pdf.name, fh, "application/pdf")})
print("http", r.status_code)
d = r.json()
keep = {k: d[k] for k in d if k in ("filename","model_used","model_version","malicious_probability","verdict","explanation")}
print(json.dumps(keep, indent=2))
if "detail" in d:
    print(d["detail"])
