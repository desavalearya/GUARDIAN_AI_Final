# Guardian AI

Postfix + milter + OpenDKIM/OpenDMARC + Guardian scan + professional Mail + SOC UIs.

## Important (real Gmail / Outlook delivery)

Postfix can deliver to real inboxes **only if**:

1. You own a domain and set DNS: **MX**, **A**, **PTR**, **SPF**, **DKIM**, **DMARC**.
2. Your host can make outbound SMTP (many home ISPs block port 25) — use a **VPS** or set `RELAYHOST` to SendGrid/Mailgun/SES.
3. From-address domain matches `MAIL_DOMAIN` so DKIM signs correctly.

This repo prints the DKIM TXT on Postfix start (`docker compose logs postfix`).

Local demo ports (avoid clash with other stacks on 25/587):

| Service | Host port |
|---|---|
| SMTP (receive) | **2525** → container 25 |
| Submission (send) | **2587** → container 587 |
| API | 8000 |
| Mail UI | 5173 |
| SOC UI | 5174 |
| Downstream demo inbox (Mailpit) | 8025 |

## Start

```powershell
cd D:\SMTP_NEW_PROJECT
docker compose up --build -d
```

Wait ~1–2 minutes for frontends’ `npm install`.

### Open

| App | URL | Login |
|---|---|---|
| Mail (Gmail-style) | http://localhost:5173 | `user@example.com` / `changeme1` |
| SOC dashboard | http://localhost:5174 | `analyst@example.com` / `changeme1` |
| Second-analyst approval | SOC login | `approver@example.com` / `changeme1` |
| Company B demo inbox | http://localhost:8025 | no login |
| API docs | http://localhost:8000/docs | JWT |

## What works now

1. **Postfix MTA** with submission + optional relay  
2. **Guardian milter** — scans inbound & outbound; rejects BLOCK/HARD_BLOCK  
3. **OpenDKIM** — signs outbound for `MAIL_DOMAIN`  
4. **OpenDMARC** — Authentication-Results on inbound path  
5. **SPF/DKIM/DMARC detector** in Guardian (`sender_auth`) using headers + DNS libs  
6. **Adaptive fast/deep inference** — URL/auth/rules first; XLM-R and document ML only when needed  
7. **Four live specialist models** — XLM-R, URL XGBoost v1, PDF v3, Office macro model  
8. **ClamAV + YARA** attachment scanning with graceful fallback  
9. **Outbound DLP**, privacy redaction, encrypted evidence vault, two-person unlock  
10. **Fraud DNA** — fuzzy/semantic/infrastructure campaign clustering and graph  
11. **HMAC-signed SIEM webhooks**, tenant scoping, rate limiting, click-time URL checks  
12. **Mail UI** — Inbox / Sent / Quarantine / Compose  
13. **SOC UI** — queues, timings, explainability, campaigns, cases, forensic report, custody  
14. **Two-server demo** — PhishProof Postfix relays allowed mail to Company B Mailpit  

## How to test each piece

### A. Health
```powershell
curl.exe -s http://localhost:8000/health
curl.exe -s http://localhost:8000/health/ready
```

### B. Mail UI
1. Open http://localhost:5173  
2. Login as `user@example.com`  
3. Inbox should show seeded clean mail; Quarantine shows phish/UNCERTAIN  

### C. SOC + SPF evidence
1. Open http://localhost:5174 as analyst  
2. Open a message → check `sender_auth` card (spf/dkim/dmarc in explanation/evidence)  
3. Model Lab → score text/URL/file  

### D. Milter + Postfix (local SMTP)
Send a raw message into Guardian Postfix on **2525**:
```powershell
# Requires Python locally; or use any SMTP client to localhost:2525
python -c "import smtplib; from email.message import EmailMessage; m=EmailMessage(); m['From']='attacker@evil.test'; m['To']='user@example.com'; m['Subject']='Urgent verify your account'; m.set_content('Click http://secure-paypal.xyz/login'); s=smtplib.SMTP('127.0.0.1',2525); s.send_message(m); s.quit(); print('sent')"
```
Then refresh SOC / Quarantine.

For the complete two-server flow:
```powershell
python scripts/demo_smtp.py fixtures/demo_eml/case1_clean.eml
```
Open http://localhost:8025. Case 1 should arrive. Repeat with Case 2; the gateway should return SMTP 550 and Company B should not receive it.

### E. Outbound through Postfix (to Gmail)
1. Set real DNS + public IP/VPS **or** `RELAYHOST` in `.env`  
2. Align From with `MAIL_DOMAIN` (demo users use `@example.com`)  
3. In Mail UI Compose → send to your Gmail  
4. Only PASS/SOFT_PASS are submitted; blocked mail stays in Guardian  

### F. DKIM DNS record
```powershell
docker compose logs postfix 2>&1 | Select-String -Pattern "DKIM|v=DKIM"
```

## Deployment status and honest limits

| Item | Status |
|---|---|
| URL/XLM-R/PDF/Office models | Integrated; large weights remain local/gitignored |
| ClamAV / YARA | Integrated; ClamAV signatures must finish initial update |
| Fraud DNA / campaigns / SIEM | Integrated; SIEM URL is disabled until configured |
| Microsoft 365 / Google connectors | Secure webhook MIME ingest is ready; external OAuth credentials are required |
| SSO | OIDC discovery/config surface is ready; production callback activation requires an IdP |
| Nginx + managed TLS | Deployment configuration still environment-specific; do not expose dev Vite/Uvicorn directly |
| Real OCR/QR bitmap decoder | Optional dependency remains; URL/HTML QR path works |
| Production SASL auth for submission (currently Docker mynetworks trust) | Simplified for lab |
| Host ports 25/587 | Use 2525/2587 here (or stop other Postfix and remap) |
| Real Gmail inbox guarantee on home Wi‑Fi | Needs VPS/DNS/relay — stack is ready |

## Stop
```powershell
docker compose down
```
