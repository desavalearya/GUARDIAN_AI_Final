# Guardian AI — Working / Run / Left

## Working now

| Area | Status |
|---|---|
| FastAPI + Postgres + Redis + JWT + Celery | Working |
| Email ingest + detector pipeline + risk/decision | Working |
| SPF / DKIM / DMARC checks (`sender_auth` + OpenDKIM/OpenDMARC) | Working |
| Postfix MTA (ports **2525** SMTP, **2587** submission) | Working |
| Guardian **pymilter** inbound/outbound scan | Working (verified: milter → ingest → decision) |
| OpenDKIM signing keys generated for `MAIL_DOMAIN` | Working (DNS TXT printed in logs) |
| OpenDMARC milter | Working |
| Mail UI (Gmail-style) Inbox/Sent/Quarantine/Compose | Working |
| SOC UI threats/queues/release/block/Model Lab | Working |
| Compose → Guardian scan → Postfix submit (PASS/SOFT_PASS only) | Working |

## How to run

```powershell
cd D:\SMTP_NEW_PROJECT
docker compose up --build -d
```

| App | URL | Login |
|---|---|---|
| Mail | http://localhost:5173 | `user@example.com` / `changeme1` |
| SOC | http://localhost:5174 | `analyst@example.com` / `changeme1` |
| API | http://localhost:8000/docs | JWT |

## How to test

1. **API** — `curl.exe -s http://localhost:8000/health`
2. **Milter/Postfix** — send SMTP to `127.0.0.1:2525`, then `docker compose logs milter --tail 20` (look for `scanned ... decision=`)
3. **Mail UI** — login, open Inbox/Quarantine, Compose
4. **SOC** — open threat, inspect `sender_auth` SPF/DKIM/DMARC evidence, release/block
5. **DKIM DNS** — `docker compose logs postfix | findstr DKIM`
6. **Smoke script** — `python scripts\smoke_test.py`
7. **Real Gmail** — set domain DNS + VPS/`RELAYHOST`, then Compose to your Gmail (PASS only)

## Left to add

- Person B trained models (URL, XLM-R, doc_struct, XGBoost fusion)
- ClamAV / YARA / OCR+QR
- Fraud DNA, campaigns, SIEM HMAC alerting
- Nginx + TLS, production SASL on submission
- Map host 25/587 (stop other Postfix or keep 2525/2587)
- Real public delivery needs your domain + DNS + outbound port 25 or relay
