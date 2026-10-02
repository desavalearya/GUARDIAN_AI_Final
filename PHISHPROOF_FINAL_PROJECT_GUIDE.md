# PhishProof — Final Project Guide

**Product name (SIH):** PhishProof  
**Engine / repo:** Guardian AI (`SMTP_NEW_PROJECT`)  
**Audience:** judges, mentors, teammates, deployment reviewers  
**Companion docs:** `PHISHPROOF_COMPLETE_FINAL.md`, `PHISHPROOF_DETAILED_SYSTEM_GUIDE.md`, `DEPLOYMENT_READINESS.md`

> **Honesty rules used in this product**  
> Fusion = **evidence consistency / variance**, never “94% probability malicious.”  
> Origin = **probable originating infrastructure**, never attacker home GPS.  
> Device-code / TOAD = heuristics. OAuth / AiTM = readiness / mock, not live capture.

---

## 1. Solution objectives

PhishProof is a **live SMTP security gateway + Cyber Cell SOC workbench** that:

1. **Intercepts mail on the real SMTP path** (Postfix + milter) before delivery.
2. **Analyses full messages in RAM** (headers, body, URLs, attachments, QR) with adaptive fast/deep ML.
3. **Explains decisions with detector evidence**, not opaque scores.
4. **Traces probable relay infrastructure** (GeoIP/ASN) without claiming attacker city/IP certainty.
5. **Clusters related fraud** via Fraud DNA fingerprints and campaign keys.
6. **Protects victim secrets** (OTP / PAN / last-4 never persisted in reports or Postgres).
7. **Supports analyst workflows**: quarantine, dual-control unlock, forensic reports, custody trail.
8. **Demonstrates two-organisation mail** — Guardian Mail ↔ Company B Mailpit — with both sides visible on the SOC dashboard.

### Demo / product claims (what we ship)

| Objective | Status in this repo |
|---|---|
| Live SMTP block / quarantine / pass | Implemented |
| Adaptive fast + async deep analysis | Implemented |
| URL XGBoost `url-xgb-v1`, PDF v3, Office, email text models | Implemented |
| Fraud DNA + campaigns + graph | Implemented |
| Dual-control raw unlock | Implemented |
| Outbound DLP heuristics | Implemented |
| ClamAV + YARA attachment scanners | Implemented (ClamAV healthy in compose) |
| Click-time URL rewrite | Implemented |
| Multi-tenant org scoping | Implemented |
| SSO / M365 / Google connectors | Readiness APIs only |
| Two-way Guardian ↔ Mailpit demo | Implemented |

---

## 2. System architecture

```
                          ┌─────────────────────────────┐
                          │     SOC Dashboard :5174     │
                          │  threats · mail flow · DNA  │
                          └──────────────▲──────────────┘
                                         │ REST / JWT
┌──────────────┐   compose    ┌──────────┴──────────┐   peer-compose
│ Guardian Mail│─────────────►│   FastAPI API :8000 │◄──────────────┐
│    :5173     │              │  ingest · mailbox   │               │
└──────▲───────┘              │  soc · cases · lab  │               │
       │                      └──────────┬──────────┘               │
       │ scanned inbox                   │                          │
       │                      ┌──────────▼──────────┐               │
       │                      │ Celery worker+Redis │               │
       │                      │ deep · DNA · SIEM   │               │
       │                      └─────────────────────┘               │
       │                                                            │
       │            ┌──────────────┐      ┌──────────────┐          │
       └────────────┤  Postgres    │      │   ClamAV     │          │
                    └──────────────┘      └──────────────┘          │
                                                                    │
   Internet / demo SMTP :2525/:2587                                 │
                    │                                               │
                    ▼                                               │
            ┌───────────────┐     milter :8891     ┌─────────────┐  │
            │    Postfix    │◄────────────────────►│   Milter    │  │
            │  DKIM/DMARC   │                      │ scan+reject │  │
            └───────┬───────┘                      └──────▲──────┘  │
                    │                                     │         │
     transport @company-b.test                    ingest /raw       │
                    │                                     │         │
                    ▼                                     │         │
            ┌───────────────┐   Release/relay back        │         │
            │ Mailpit :8025 │─────────────────────────────┘         │
            │ SMTP   :1025  │   (Company B server)                  │
            └───────▲───────┘                                       │
                    │  mirror copy via Mailpit HTTP API             │
                    └───────────────────────────────────────────────┘
```

### Two-server mail (bidirectional)

| Direction | Path | Visible where |
|---|---|---|
| **Guardian → Company B** | Guardian Mail compose → API scan → Postfix → transport to Mailpit SMTP | Guardian **Sent**, Mailpit UI `:8025`, SOC **Mail flow** |
| **Company B → Guardian** | Guardian Mail “Compose as Company B” (or Mailpit **Release**) → Postfix+milter scan → local delivery | Guardian **Inbox**, Mailpit copy (mirror), SOC **Mail flow** |

---

## 3. End-to-end workflows

### 3.1 Inbound SMTP (attack / external mail)

1. Client submits SMTP to Postfix (`:2525` / `:2587`).
2. Milter receives full message at `eom`.
3. Milter POSTs raw MIME to `POST /api/v1/ingest/raw`.
4. Pipeline parses → redacts secrets → runs orchestrator (fast, maybe deep).
5. Risk engine fuses detectors → decision ladder (`PASS` … `HARD_BLOCK`).
6. If `HARD_BLOCK` / `BLOCK` → milter **REJECT 550**.
7. Else accept; quarantine/review mail is stored but hidden from user Inbox.
8. Worker may run `deep_analyze_email`, `generate_fraud_dna`, `emit_siem_event`.

### 3.2 Outbound Guardian compose

1. User sends from Guardian Mail.
2. API runs `ingest_and_analyze` as **outbound** (DLP included).
3. On PASS/SOFT_PASS → `submit_via_postfix` (optional URL rewrite).
4. Postfix signs (DKIM) and routes `@company-b.test` to Mailpit.

### 3.3 Company B → Guardian (peer)

1. `POST /api/v1/mailbox/peer-compose` mirrors into Mailpit HTTP API.
2. Same content submitted through Postfix.
3. Milter scans as inbound (non-local From).
4. Delivered to Guardian mailbox if PASS.

### 3.4 SOC investigation

1. Analyst opens threat / mail-flow row.
2. Sees timings, detectors, Fraud DNA, origin map point.
3. Can preserve vault evidence, request dual-control unlock, export forensic report / FIR text.

---

## 4. Tech stack (detail)

### Runtime & orchestration
| Layer | Choice | Why |
|---|---|---|
| Containers | Docker Compose | Reproducible SIH demo stack |
| API | FastAPI + Uvicorn | Async-friendly REST, OpenAPI at `/docs` |
| Workers | Celery + Redis | Deep analysis / DNA / SIEM off SMTP hot path |
| DB | PostgreSQL 15 | Cases, emails, custody, multi-tenant orgs |
| Cache / broker | Redis 7 | Celery + rate limits + short cache |
| MTA | Postfix | Real SMTP gateway + transport maps |
| Filter | pymilter Guardian milter | Inline reject/accept |
| Auth signing | OpenDKIM + OpenDMARC | Outbound authenticity story |
| Catch-all inbox (Company B) | Mailpit | Real SMTP + browser UI |
| AV | ClamAV 1.4 | Attachment malware signatures |
| Frontends | React + Vite | SOC `:5174`, Guardian Mail `:5173` |

### Backend libraries (high level)
- **SQLAlchemy + Alembic** — models & migrations `0001`…`0007`
- **Pydantic Settings** — typed config from `.env`
- **PyJWT** — mailbox / SOC auth
- **httpx** — milter→API, Mailpit mirror, SIEM webhook
- **cryptography / Fernet** — vault + URL rewrite tokens
- **yara-python** — optional rule hits under `data/yara/`
- **ML stack** — joblib/xgboost/transformers runtimes under `models/`

### ML models in use
| Model | Path / id | Role |
|---|---|---|
| URL | `models/url/v1` (`url-xgb-v1`) | Phishing URL score |
| PDF | `models/PDF_v3` | Malicious PDF features |
| Office | Office model pack | Macro / doc risk |
| Email text | Email / XLM-R style pack | Body language risk |

Heuristics remain fallbacks when models are cold or features missing.

---

## 5. Services implemented (every Compose service)

| Service | Image / build | Ports | Responsibility |
|---|---|---|---|
| **postgres** | `postgres:15-alpine` | `5432` | Durable store for emails, decisions, cases, DNA, unlocks, orgs |
| **redis** | `redis:7-alpine` | `6379` | Celery broker/backend; rate-limit counters |
| **api** | `backend/Dockerfile` | `8000` | FastAPI: health, auth, ingest, mailbox, SOC, cases, lab, links, connectors |
| **worker** | same image | (internal) | `deep_analyze_email`, `generate_fraud_dna`, `emit_siem_event`, retention tasks |
| **milter** | `gateway/milter` | `8891` | SMTP filter; calls ingest; REJECT on hard block |
| **postfix** | `gateway/postfix` | `2525→25`, `2587→587` | Accept mail, milter hook, DKIM, route demo domain to Mailpit |
| **receiver** | `axllent/mailpit:v1.21` | `8025` UI, `1025` SMTP | Company B mailbox; SMTP relay back to Postfix for Release |
| **clamav** | `clamav/clamav:1.4` | `3310` | Attachment scanning used by deep/engine path |
| **mail-client** | `node:20` Vite | `5173` | Guardian Mail (Mailpit-style UI + two-way compose) |
| **dashboard** | `node:20` Vite | `5174` | SOC: threats, cases, map/DNA, **mail flow**, model lab |

### Health endpoints
- `GET /health` → process alive  
- `GET /health/ready` → database, redis, four models, clamav  

---

## 6. Backend capability map

| Capability | Primary files | Notes |
|---|---|---|
| Adaptive orchestration | `backend/detection/orchestrator.py`, `engine.py` | Fast path always; deep sync/async by risk band |
| Auth / SPF-DKIM-DMARC | `detection/auth_checks.py` | Prefer Authentication-Results |
| Origin infra | `detection/origin.py`, `relay.py`, `intel/geoip.py` | Honest disclaimers |
| URL ML + heuristics | `detection/url_ml.py`, `url_heuristics.py` | Cacheable URL scores |
| QR / quishing | `detection/qr.py` | Decode → URL detectors |
| ATO / TOAD heuristics | `detection/ato.py`, `signals.py` | Not live OAuth steal |
| DLP outbound | `detection/dlp.py` | API keys / secrets patterns |
| ClamAV / YARA | `detection/engine.py` | Deep/attachment path |
| Risk fusion | `backend/risk/engine.py` | Variance / agreement, decision ladder |
| Pipeline | `backend/email/pipeline.py` | Parse → detect → persist → queue jobs |
| URL rewrite | `backend/email/link_rewrite.py`, `api/links.py` | Click-time interstitial |
| Fraud DNA | `backend/cases/fraud_dna.py` | Fuzzy hash + embedding + cluster |
| Cases / FIR / vault | `backend/cases/service.py`, `privacy/*` | Masked forensic outputs |
| Mailbox | `backend/api/mailbox.py` | Folders, compose, **peer-compose** |
| Mailpit mirror | `backend/email/mailpit_client.py` | HTTP `/api/v1/send` copy |
| Dual-control unlock | `backend/api/cases.py` | request → approve → unlock |
| Rate limit | `backend/middleware.py` | Redis sliding window |
| Multi-tenant | `models.Organization`, migration `0007` | Org scoped queries |
| Connectors / OIDC | `api/connectors.py`, `api/auth.py` | Readiness, not live sync |

---

## 7. Frontend surfaces

### Guardian Mail (`frontend/mail-client`) — Mailpit-aligned
- Dark mailbox layout (sidebar + list + reader)
- Search, live refresh, decision tags
- Message tabs: **HTML / Text / Headers / Raw**
- Folders: Mailbox (all), Inbox, Sent, Quarantine
- **Compose → Company B** (Guardian outbound)
- **Compose as Company B →** (peer path + Mailpit mirror)
- Links to Mailpit UI and SOC

### SOC Dashboard (`frontend/dashboard`)
- Threat inbox / high-risk / uncertain queues
- Case intake, forensic report, dual-control unlock
- Map + Fraud DNA graph
- **Mail flow** tab — direction, from/to, path, decision for both orgs
- Model Lab for isolated model checks
- EN / HI / MR i18n

---

## 8. File structure (what each area contains)

```
SMTP_NEW_PROJECT/
├── docker-compose.yml          # All services, ports, demo receiver relay
├── .env / .env.example         # Secrets & demo domain settings
├── alembic.ini                 # Migration runner config
├── README.md / STATUS.md       # Quick start & status
├── PHISHPROOF_*.md             # Specs & this guide family
├── DEPLOYMENT_READINESS.md     # Ship checklist (no cloud deploy required)
│
├── backend/
│   ├── main.py                 # FastAPI app + routers + rate limit
│   ├── config.py               # Settings (DB, models, ClamAV, Mailpit, SSO…)
│   ├── models.py               # ORM: Email, Decision, Campaign, FraudFingerprint,
│   │                           # Organization, UnlockRequest, AuditLog…
│   ├── schemas.py              # Pydantic API models
│   ├── database.py             # Engine + SessionLocal
│   ├── middleware.py           # Redis rate limiter
│   ├── entrypoint.py           # api / worker process launcher
│   ├── seed.py                 # Demo users + org
│   ├── api/
│   │   ├── auth.py             # Login JWT + OIDC config readiness
│   │   ├── health.py           # liveness / readiness
│   │   ├── ingest.py           # Raw SMTP/API ingest + serialize_email
│   │   ├── mailbox.py          # Folders, compose, peer-compose, demo-peers
│   │   ├── soc.py              # Queues, upload-eml, release/block
│   │   ├── cases.py            # Alerts, preserve, unlock*, campaigns, map, FIR
│   │   ├── lab.py              # Model lab endpoints
│   │   ├── links.py            # Rewritten URL click-through
│   │   ├── connectors.py       # M365/Google readiness status
│   │   └── deps.py             # Auth / RBAC dependencies
│   ├── detection/              # All detectors + orchestrator + DLP
│   ├── email/                  # parser, pipeline, smtp_submit, link_rewrite, mailpit_client
│   ├── risk/                   # Fusion + decision ladder
│   ├── cases/                  # Case service + fraud_dna
│   ├── privacy/                # Redaction + vault
│   ├── intel/                  # GeoIP + lists
│   ├── workers/                # Celery app + tasks
│   └── alembic/versions/       # 0001…0007 schema evolution
│
├── gateway/
│   ├── milter/guardian_milter.py
│   └── postfix/                # Dockerfile, entrypoint, DKIM/DMARC conf
│
├── frontend/
│   ├── mail-client/            # Guardian Mail (Mailpit-style)
│   └── dashboard/              # SOC console
│
├── models/                     # Trained artifacts (often gitignored large files)
├── data/                       # GeoIP, YARA rules, intel seeds
├── fixtures/demo_eml/          # Demo cases 1–5
└── scripts/                    # demo_smtp.py, eval & smoke helpers
```

---

## 9. Decision ladder (SOC language)

Typical outcomes (exact thresholds live in `risk/engine.py`):

| Decision | Meaning for demo |
|---|---|
| `PASS` / `SOFT_PASS` | Deliver / show in Inbox |
| `HUMAN_REVIEW` | Hold for analyst |
| `QUARANTINE` | Held; not in user Inbox |
| `BLOCK` / `HARD_BLOCK` | SMTP reject or outbound forbid |

Fusion emphasises **agreement vs conflict** across detectors (`confidence_state`, `agreement_metric`), not a fake probability of guilt.

---

## 10. Demo accounts & URLs

| Surface | URL | Login |
|---|---|---|
| Guardian Mail | http://localhost:5173 | `user@example.com` / `changeme1` |
| Company B Mailpit | http://localhost:8025 | none |
| SOC | http://localhost:5174 | `analyst@example.com` / `changeme1` |
| Dual-control approver | SOC | `approver@example.com` / `changeme1` |
| API docs | http://localhost:8000/docs | — |
| SMTP gateway | `localhost:2525` (25), `localhost:2587` (587) | — |

### Quick bidirectional check
1. Guardian Mail → **Compose → Company B** → see message in Mailpit `:8025` and SOC **Mail flow**.
2. Guardian Mail → **Compose as Company B** → see Mailpit copy + Guardian Inbox (if PASS) + SOC **Mail flow**.
3. Optional: in Mailpit, use **Release** to `@example.com` (relay host = Postfix).

---

## 11. API surface (grouped)

- **Auth:** `/api/v1/auth/login`, `/api/v1/auth/oidc/config`
- **Health:** `/health`, `/health/ready`
- **Ingest:** `/api/v1/ingest/raw`
- **Mailbox:** `/folders/{all|inbox|sent|quarantine}`, `/compose`, `/peer-compose`, `/demo-peers`
- **SOC:** `/emails`, `/queues/{HIGH_RISK|UNCERTAIN}`, `/upload-eml`, release/block
- **Cases:** alerts, intake, report, FIR, preserve, unlock request/approve/unlock, campaigns, graph, map-points
- **Lab:** text / URL / PDF / Office scan helpers
- **Links:** rewritten URL resolve
- **Connectors:** status readiness

---

## 12. What is intentionally not claimed

- Live Microsoft 365 / Google Workspace continuous sync (connectors are readiness stubs).
- Live OAuth / AiTM credential harvesting.
- Attacker residential GPS from GeoIP.
- “Probability % malicious” marketing language.
- Cloud production deploy (repo is **deployment-ready**; local Compose is the SIH runtime).

---

## 13. Operate the stack

```powershell
cd D:\SMTP_NEW_PROJECT
docker compose ps
curl.exe http://localhost:8000/health/ready
```

Do **not** run `docker compose up --build` unless Dockerfiles/`requirements.txt` changed. Code under `backend/` and frontends is volume-mounted — `docker compose restart api worker mail-client dashboard` is enough for most edits.

Stop:

```powershell
docker compose down
```

---

## 14. One-line closing

**PhishProof is a forensic-grade SMTP gateway that blocks with evidence, explains fusion honestly, correlates Fraud DNA campaigns, and proves the story on a live two-server Guardian ↔ Company B mail path visible to both mail UIs and the SOC dashboard.**
