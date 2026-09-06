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
| API docs | http://localhost:8000/docs | JWT |

## What works now

1. **Postfix MTA** with submission + optional relay  
2. **Guardian milter** — scans inbound & outbound; rejects BLOCK/HARD_BLOCK  
3. **OpenDKIM** — signs outbound for `MAIL_DOMAIN`  
4. **OpenDMARC** — Authentication-Results on inbound path  
5. **SPF/DKIM/DMARC detector** in Guardian (`sender_auth`) using headers + DNS libs  
6. **Heuristic detectors** + confidence/decision pipeline  
7. **Mail UI** — Inbox / Sent / Quarantine / Compose (professional layout)  
8. **SOC UI** — threats, queues, release/block, Model Lab  
9. **Compose → scan → Postfix submit** when decision is PASS/SOFT_PASS  

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

### E. Outbound through Postfix (to Gmail)
1. Set real DNS + public IP/VPS **or** `RELAYHOST` in `.env`  
2. Align From with `MAIL_DOMAIN` (demo users use `@example.com`)  
3. In Mail UI Compose → send to your Gmail  
4. Only PASS/SOFT_PASS are submitted; blocked mail stays in Guardian  

### F. DKIM DNS record
```powershell
docker compose logs postfix 2>&1 | Select-String -Pattern "DKIM|v=DKIM"
```

## Left to add / integrate

| Item | Status |
|---|---|
| Person B trained models (URL, XLM-R, doc_struct, XGBoost) | Not integrated — heuristics/stubs |
| ClamAV / YARA / real OCR+QR | Not wired |
| Fraud DNA / campaigns / SIEM HMAC alerts | Not built |
| Nginx + TLS reverse proxy | Not built |
| Production SASL auth for submission (currently Docker mynetworks trust) | Simplified for lab |
| Host ports 25/587 | Use 2525/2587 here (or stop other Postfix and remap) |
| Real Gmail inbox guarantee on home Wi‑Fi | Needs VPS/DNS/relay — stack is ready |

## Stop
```powershell
docker compose down
```
