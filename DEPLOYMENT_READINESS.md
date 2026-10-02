# PhishProof Deployment Readiness (No Deployment Performed)

This repository is prepared for a controlled pilot. It has **not** been deployed to a cloud, public IP, domain, Microsoft 365 tenant, Google Workspace tenant, IdP, or SIEM.

## Runtime architecture

```text
Sender / Company A
        │ SMTP
        ▼
Postfix gateway → milter → FastAPI fast path
        │                        ├─ auth / URL / DLP / rules (synchronous)
        │                        └─ XLM-R / document ML (conditional or Celery)
        │
        ├─ BLOCK/HARD_BLOCK → SMTP 550
        └─ allowed → Company B downstream SMTP (Mailpit in demo)

PostgreSQL = tenant-scoped system of record
Redis = cache, rate limiter, Celery broker
Worker = deferred deep analysis, Fraud DNA, SIEM, retention
ClamAV/YARA = attachment-only security
SOC = analyst UI; Mail Client = end-user UI
```

## Why hybrid synchronous/asynchronous

- SMTP waits only for controls required to make a safe immediate decision.
- Expensive models run inline for suspicious/uncertain/high-value content or relevant attachments.
- Very low-risk messages can be accepted with deep analysis queued.
- Fraud DNA, SIEM delivery and campaign intelligence never block SMTP.
- API responses expose `fast_path_ms`, `deep_path_ms`, `total_analysis_ms`, `deep_status`, and `models_run`.

Configure:

```env
ANALYSIS_MODE=adaptive
DEEP_SYNC_MIN_RISK=15
DEEP_SYNC_MAX_RISK=90
ASYNC_DEEP_ENABLED=true
SMTP_SCAN_TIMEOUT_SECONDS=20
```

Use `ANALYSIS_MODE=full` only for evaluation; it is not the recommended production gateway mode.

## Required secrets before any pilot

Generate independent random values for:

- `JWT_SECRET`
- `HMAC_SECRET`
- `VAULT_SECRET`
- `INGEST_API_KEY`
- `SIEM_HMAC_SECRET`
- `URL_REWRITE_SECRET`
- `CONNECTOR_WEBHOOK_SECRET`

Never reuse one secret for another purpose. Do not commit `.env`.

## Production edge still environment-specific

Before public exposure, place a reverse proxy/load balancer in front of the API and production-built frontends:

- TLS 1.2+ / HSTS
- real DNS and certificates
- request/body limits matching API limits
- trusted proxy headers
- restricted CORS origins
- WAF/rate-limit policy
- private network access to PostgreSQL, Redis, ClamAV, worker and milter

Do not expose development Vite servers, PostgreSQL, Redis or ClamAV publicly.

## Multi-tenancy

`Organization` boundaries scope:

- users
- emails
- campaigns/Fraud DNA comparisons
- DLP policies
- SOC queues, cases, map and reports

The demo migration creates the `default` organization. A production onboarding API/admin workflow should create organizations and domains; do not hand-edit tenant IDs.

## External integrations

### SIEM

Set `SIEM_WEBHOOK_URL`. Events contain hashes/domains/decisions—not message bodies or victim secrets—and include:

```http
X-PhishProof-Signature: sha256=<HMAC>
```

The receiver must compute HMAC-SHA256 over the exact request body using `SIEM_HMAC_SECRET`.

### Microsoft 365 / Google Workspace

`POST /api/v1/connectors/{m365|google|generic}/messages` accepts base64 RFC822 MIME with `X-Connector-Secret`. This is a deployment adapter, not an automatically activated cloud subscription. Provider OAuth/subscription credentials are required and must be configured by the customer.

### SSO

`GET /api/v1/auth/oidc/config` reports generic OIDC readiness. Configure issuer/client/secret and implement/validate the customer-specific callback policy before disabling local JWT login.

## Two-SMTP-server demo

1. Start the stack after building changed backend dependencies:

   ```powershell
   docker compose up --build -d
   ```

2. Wait for `docker compose ps` and `GET /health/ready`.
3. Open:
   - SOC: http://localhost:5174
   - Mail Client: http://localhost:5173
   - Company B receiver: http://localhost:8025
4. Send clean mail:

   ```powershell
   python scripts/demo_smtp.py fixtures/demo_eml/case1_clean.eml
   ```

5. Verify it appears in Company B.
6. Send Case 2. Verify SMTP 550 and no Company B delivery.
7. Open SOC and show detector evidence, path timing, Fraud DNA, case and forensic report.

The receiver is Mailpit: a real downstream SMTP listener and browser inbox for local demonstration, not a production mailbox server.

## Dual-control evidence access

1. Preserve exhibit.
2. Analyst A requests raw access with justification.
3. Different analyst/admin approves.
4. Approved request is consumed on unlock.
5. Every step is written to custody.

Demo approver: `approver@example.com / changeme1`.

## Capacity and cost controls

- URL model results cached in Redis.
- Document/AV models run only for attachments.
- Fraud DNA only runs for review/quarantine/block outcomes.
- No paid LLM API is used in the mail path.
- Rate limits protect login and ingest.
- Scale API/milter and Celery workers independently.
- Add CPU/RAM limits after profiling on target hardware.

## Verification gates before a pilot

- [ ] All Alembic migrations applied through `0007_multi_tenant`
- [ ] `/health/ready`: DB/Redis/models OK; ClamAV OK or explicitly disabled
- [ ] All five fixture decisions checked
- [ ] SMTP clean delivery and malicious rejection checked
- [ ] DLP AWS/private-key test blocked outbound
- [ ] Two-person unlock tested with two users
- [ ] SIEM signature verified by receiver
- [ ] Cross-tenant API isolation tests pass
- [ ] Backup/restore and secret rotation rehearsed
- [ ] TLS, DNS, DKIM, SPF, DMARC and relay configured
- [ ] Retention policy legally approved

## Honest remaining production work

- Customer-specific OIDC callback and provider OAuth subscription activation
- Infrastructure-as-code for the chosen cloud/on-prem platform
- HA PostgreSQL/Redis, backups, monitoring and alerting
- Load/soak/chaos testing and SMTP retry/queue policy tuning
- Security review, penetration test and data-protection/legal review
- Optional real bitmap QR/OCR dependency

These cannot be truthfully completed without a target environment, credentials, traffic expectations and organizational policies.
