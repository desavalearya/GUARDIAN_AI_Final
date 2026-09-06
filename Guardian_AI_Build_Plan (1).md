# Guardian AI — Complete Project Build Plan

**Version:** Merged (Original Architecture + Real-World Hardening Additions)
**Audience:** A team starting from zero, building this as a real, sellable project (not a hackathon demo)

---

## 1. What Exactly Are We Building

Guardian AI is an **AI-powered email security platform** that sits between the outside world and an organization's mailboxes, and also connects directly into cloud mailboxes (Microsoft 365 / Google Workspace) via API. Every email — inbound, internal, and outbound — is analyzed by multiple independent detection engines (text, URL, credentials, images/QR, attachments, sender authentication, and behavior), fused into one explainable risk score, checked against known attacker fingerprints (Fraud DNA) and campaigns, and then delivered, quarantined, or blocked.

The core idea, unchanged from the original design:

> Don't treat a phishing email as one thing to classify. Treat it as an attack with multiple independent pieces of evidence, correlate that evidence, and explain the decision.

What's new in this merged version, layered on top without changing the core:

1. **Hybrid ingestion** — a traditional SMTP gateway (Postfix + milter) *and* a direct API connector (Graph API / Gmail API), so we see inbound, internal, and post-delivery mail — not just what crosses the gateway.
2. **Behavioral / BEC detection** — a sender-recipient relationship graph that flags social-engineering attacks that carry no malicious link or attachment at all.
3. **Domain intelligence + external threat feeds** — WHOIS/domain-age lookups and free threat-intel APIs (VirusTotal, URLhaus, AbuseIPDB), so we're not relying only on our own trained models for brand-new malicious infrastructure.
4. **URL rewriting + click-time re-check** — every link is rewritten so it's re-verified at the moment someone clicks it, not just once at delivery time.
5. **Auto-remediation hooks** — on a high-confidence compromise, the system can force a logout/password reset via the identity provider, not just quarantine the email.
6. **(Stretch) CAPTCHA-aware rendering, sandbox detonation, sign-in anomaly correlation** — for later phases, listed so the team knows the roadmap even if not built in v1.

Everything else — the phishing/URL/credential/image/malware detectors, the Fraud DNA and campaign correlation system, the honeypot, the Red Team AI testing tool, and the quarantine/decision engine — is the original design, kept as-is.

---

## 2. How the Whole Thing Actually Flows (End to End)

```
                         EMAIL SOURCE
              (SMTP gateway  OR  M365/Gmail API pull)
                              │
                              ▼
                       EMAIL INGESTION
              parse headers, sender, body, URLs,
              images, QR codes, attachments
                              │
                              ▼
                 ┌────────────┴────────────┐
                 ▼                         ▼
         AUTHENTICATION CHECK      DOMAIN INTELLIGENCE
         SPF / DKIM / DMARC        WHOIS age + threat-intel
                 │                 feeds (VirusTotal/URLhaus)
                 │                         │
                 └────────────┬────────────┘
                              ▼
                    PARALLEL DETECTION LAYER
   ┌──────────┬──────────┬───────────┬───────────┬──────────┐
   ▼          ▼          ▼           ▼           ▼          ▼
 Text       URL      Credentials  Image/QR   Attachment  Behavior
 (XLM-R)  (TF-IDF+LR)  (Regex+     (OCR+QR   (ClamAV+    (BEC graph
                        entropy)    decode)   YARA+pefile) anomaly)
   │          │          │           │           │          │
   └──────────┴──────────┴─────┬─────┴───────────┴──────────┘
                              ▼
              CROSS-SIGNAL CONFIDENCE + RISK FUSION
        (one consolidated module — XGBoost calibrator takes
         every detector score + domain age + threat-intel hit
         as input features, outputs one risk number 0-100)
                              │
                              ▼
                   FRAUD DNA + CAMPAIGN MATCH
          (has this attacker/pattern been seen before?)
                              │
                              ▼
                       DECISION ENGINE
        ┌───────────┬────────────┬────────────┬──────────┐
        ▼           ▼            ▼            ▼          ▼
      PASS      SOFT PASS    QUARANTINE      BLOCK   HUMAN REVIEW
                                   │                       │
                                   ▼                       ▼
                          Analyst dashboard         Analyst decides
                                   │                       │
                                   └───────────┬───────────┘
                                               ▼
                             If confirmed malicious + high risk:
                             AUTO-REMEDIATION (force logout /
                             password reset via IdP API)
                                               │
                                               ▼
                                  Feedback → model governance
                                  (retrain, drift tracking)
```

And separately, always running in the background:

```
Every link in every delivered email
        │
        ▼
  Rewritten as a tracked redirect URL
        │
        ▼
  At the moment someone clicks it →
  re-checked live against URL model + threat feeds
        │
        ▼
  Safe → redirect to real page
  Unsafe → block + alert
```

---

## 3. Complete Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Backend framework** | Python, FastAPI, Uvicorn | Core API and services |
| **Background jobs** | Celery + Redis | Async processing of email analysis, sandboxing, retries |
| **Database** | PostgreSQL | Emails, decisions, Fraud DNA, campaigns, behavioral graph |
| **Cache/queue** | Redis | Celery broker, click-time URL token store |
| **Auth** | JWT + bcrypt | Dashboard/API authentication |
| **Email gateway** | Postfix + pymilter | Traditional SMTP interception |
| **Cloud mail connector** | Microsoft Graph API, Gmail API | API-based ingestion of inbound/internal/outbound mail |
| **Phishing text model** | PyTorch + HuggingFace Transformers, XLM-RoBERTa | Multilingual phishing-intent classification |
| **URL model** | scikit-learn, TF-IDF (char n-gram) + Logistic Regression | Lexical/structural URL classification |
| **Domain intelligence** | `python-whois`, WHOIS API | Domain age lookup |
| **Threat intel feeds** | VirusTotal API, URLhaus (abuse.ch), AbuseIPDB | Known-bad domain/IP/hash checks |
| **Credential detection** | Python `re`, custom Shannon entropy function | Secret/credential-request detection |
| **Image/QR analysis** | OpenCV, Tesseract OCR (`pytesseract`), `pyzbar` | Text and QR extraction from images |
| **Malware scanning** | ClamAV (daemon), `yara-python`, `pefile`, hashlib | Static attachment scanning |
| **Sandbox detonation (stretch)** | CAPEv2 (self-hosted) | Dynamic analysis of attachments that pass static checks |
| **Sender auth checks** | `checkdmarc`, `dkimpy` | SPF/DKIM/DMARC validation |
| **Behavioral/BEC detection** | scikit-learn (Isolation Forest), PostgreSQL | Sender-recipient relationship anomaly scoring |
| **Fraud DNA / similarity** | `ssdeep` or TLSH (fuzzy hashing), `sentence-transformers` (text embeddings) | Fingerprinting and matching attacks across campaigns |
| **Risk fusion / calibration** | XGBoost | Combines all detector + intel scores into one calibrated risk number |
| **URL rewriting service** | FastAPI + Redis (signed tokens) | Click-time re-verification |
| **CAPTCHA-aware rendering (stretch)** | Playwright | Render pages behind CAPTCHA walls for inspection |
| **Auto-remediation** | Microsoft Graph API / Okta API | Force logout / password reset on confirmed compromise |
| **Frontend dashboard** | React, TypeScript, Material UI, Recharts | Analyst dashboard, quarantine review, campaign view |
| **Deployment** | Docker, Docker Compose, Nginx, TLS | Containerized services, reverse proxy |
| **Secrets management** | HashiCorp Vault (or `.env` + Docker secrets for MVP) | DKIM keys, JWT secrets, API keys |
| **Version control / CI** | Git, GitHub, GitHub Actions | Source control, automated testing/build |

---

## 4. What To Install Before Writing Any Code

Do this once, as a team, before anyone touches the actual project.

### 4.1 Core system tools
- **Git** — version control (`git --version` to check if already installed)
- **Docker Desktop** (or Docker Engine + Docker Compose on Linux) — everything (Postgres, Redis, ClamAV, the app itself) will run in containers so every team member has an identical environment
- **Python 3.11+** — backend and ML
- **Node.js 20+ and npm** — frontend
- **VS Code** (or your editor of choice) — recommended extensions: Python, Docker, ESLint, Prettier

### 4.2 System-level packages (needed by some Python libraries)
- `tesseract-ocr` (system binary — `pytesseract` is just a Python wrapper around it)
- `libzbar0` (needed by `pyzbar` for QR decoding)
- ClamAV (`clamav`, `clamav-daemon`) — can also be run as a Docker container instead of installing natively
- YARA (system binary, `yara-python` wraps it)

### 4.3 Accounts / API keys to register for (do this early, some take time to approve)
- **VirusTotal** — free API key for threat intel lookups
- **Microsoft Azure App Registration** — needed for Graph API access (mail read/actions) — this can take a bit to set up correctly with the right permission scopes, start early
- **Google Cloud Console project** — needed for Gmail API access, same reasoning
- **A test domain** — you'll want a real (or sandboxed) domain to configure SPF/DKIM/DMARC records against for testing, and to run your honeypot

### 4.4 Datasets to download in advance (for training/testing)
- **Phishing email text**: Nazario phishing corpus, SpamAssassin public corpus (for legitimate mail baseline)
- **Phishing URLs**: PhishTank (free feed), URLhaus (free feed)
- **Legitimate URLs (negative class)**: Common Crawl domain lists or Tranco top-sites list
- **Malware samples for testing** (handle carefully, isolated environment only): controlled datasets like theZoo or EICAR test files — never live malware on a personal machine
- **Legitimate email flow baseline for BEC**: the Enron email dataset works well as a stand-in for realistic organizational communication patterns

---

## 5. Step-by-Step Build Workflow

This is written so someone with no prior experience building a system like this can follow it in order. Each phase assumes the previous one works before moving on. Don't skip ahead.

### Phase 0 — Team & Repo Setup (Week 0)
1. Create a GitHub repository, set up branch protection on `main`.
2. Agree on folder structure up front (see Section 6).
3. Set up a shared `.env.example` file listing every environment variable the project will need (API keys, DB credentials) — never commit real secrets.
4. Assign rough role ownership (see Section 7) so people aren't stepping on each other.
5. Set up a project board (GitHub Projects, Trello, whatever) mapped to the phases below.

### Phase 1 — Foundation Skeleton
1. Write a `docker-compose.yml` that spins up: PostgreSQL, Redis, and an empty FastAPI service. Confirm all three start and the FastAPI service returns a "hello world" on a health-check endpoint.
2. Set up Alembic (or a simple SQL migration tool) for database schema versioning from day one — don't hand-edit the database.
3. Build basic JWT authentication for the API (register/login endpoints, protected routes).
4. Confirm Celery is wired to Redis and can run a trivial background task end to end.

**Checkpoint:** you can hit an authenticated API endpoint, it queues a Celery task, and the task writes something to Postgres. Nothing email-related yet — this is just proving the skeleton works.

### Phase 2 — Email Ingestion
1. **Gateway path**: set up Postfix locally (in a container) with `pymilter` calling into your FastAPI backend for every incoming message.
2. **API path**: register the Azure app and Google Cloud project, get read access to a test mailbox, and write a small poller/webhook service that pulls new mail via Graph API / Gmail API.
3. Write one shared **email parser module** used by both ingestion paths — it should extract: headers, sender, recipient, subject, body (plain + HTML), URLs, embedded images, attachments. Both ingestion paths should hand off to this same parser so the rest of the pipeline never needs to know which path the email came in through.

**Checkpoint:** an email sent to your test setup (via either path) lands in Postgres as a structured record with all fields extracted.

### Phase 3 — Individual Detectors (build and test each in isolation before wiring together)
Build these one at a time, each as its own service/module with its own unit tests, each taking a parsed email and returning a score + explanation:

1. **Sender authentication** — SPF/DKIM/DMARC check using `checkdmarc`/`dkimpy`. This is the simplest, do it first to build momentum.
2. **Credential detector** — regex patterns + Shannon entropy function. Also simple, no ML needed.
3. **Domain intelligence** — WHOIS age lookup + VirusTotal/URLhaus check on every extracted URL and attachment hash.
4. **URL model** — start by training the TF-IDF + Logistic Regression model offline in a notebook using PhishTank/URLhaus data, evaluate accuracy, then wrap it as a loadable model the API calls.
5. **Image/QR pipeline** — OpenCV + Tesseract OCR + pyzbar. Extracted text/URLs get sent back through steps 3–4 above (reuse, don't rebuild).
6. **Text phishing model (XLM-R)** — start with a pretrained multilingual model from HuggingFace, fine-tune on your phishing corpus + SpamAssassin (legit) as the two classes. This is the most compute-heavy step — budget real time for it.
7. **Malware scanner** — ClamAV daemon + YARA rules + pefile static checks on attachments.

**Checkpoint:** each detector, given a test email, independently returns a sensible score. Test each with known-good and known-bad samples before moving on.

### Phase 4 — Behavioral / BEC Detector (the new addition)
1. Build a Postgres table tracking sender↔recipient pairs: frequency, typical time-of-day, whether financial/urgent language has appeared before between this pair.
2. Once you have some volume of "normal" mail flowing through (use the Enron dataset to bootstrap this if you don't have real traffic yet), train an Isolation Forest on the relationship features.
3. Score new emails: does this sender-recipient pair, tone, and request type look normal for them?

**Checkpoint:** an email from a "never-before-seen" domain impersonating a normal contact, asking for something urgent/financial, gets flagged — even with no malicious URL or attachment.

### Phase 5 — Fusion, Risk, and Decision
1. Build **one** consolidated fusion module (not four separate ones) — an XGBoost model that takes every detector's score, the domain-age/threat-intel results, and the behavioral score as input features, and outputs a single calibrated 0–100 risk number plus a CONFIDENT/UNCERTAIN flag based on how much the individual signals agree.
2. Build the Decision Engine — simple threshold/policy logic on top of the risk number: PASS / SOFT PASS / QUARANTINE / BLOCK / HUMAN REVIEW.
3. Decide and document your fail-open vs fail-closed policy now (what happens if this service is down) — don't leave it undecided.

**Checkpoint:** a full test email goes in, and a single risk score + decision comes out, with a breakdown of which detectors contributed what.

### Phase 6 — Fraud DNA & Campaign Correlation
1. On any QUARANTINE/BLOCK decision, generate a Fraud DNA record: sender, domains, URLs, attachment hash, techniques detected, fuzzy hash (ssdeep/TLSH) of the email body, and a text embedding (sentence-transformers) of the message.
2. Write a similarity-matching job: compare new Fraud DNA records against historical ones using fuzzy-hash distance + embedding cosine similarity, cluster matches into campaigns.

**Checkpoint:** sending three variant phishing emails (same tactic, slightly different domains) gets them grouped under one campaign ID.

### Phase 7 — URL Rewriting & Click-Time Re-Check
1. Build a small redirect service: every URL in a delivered email gets rewritten to `yourdomain.com/r/{signed-token}`.
2. On click, the service re-runs the URL through the URL model + threat-intel check *live*, then redirects to the real destination if still safe, or blocks with a warning page if not.

**Checkpoint:** a URL that was scored "safe" at delivery time, then added to a threat-intel blocklist an hour later, gets blocked on click even though it passed the original scan.

### Phase 8 — Auto-Remediation
1. On CONFIRMED + very-high-risk decisions, trigger an API call to the identity provider (Graph API / Okta) to force a logout/password reset on the affected account.
2. Log every auto-remediation action immutably — this needs to be auditable.

**Checkpoint:** a simulated high-confidence account-compromise email triggers an automatic forced logout in your test tenant.

### Phase 9 — Dashboard
1. Build the React dashboard: threat list, individual email drill-down showing every detector's contribution, quarantine review queue, campaign view, Fraud DNA view.
2. Analyst actions (release/block/mark false positive) should write feedback into the database — this feedback is what you'll eventually use for model governance/retraining.

### Phase 10 — Supporting Systems
1. **Honeypot** — stand up a few decoy mailboxes, route anything they receive straight into the Fraud DNA pipeline as free threat intelligence.
2. **Red Team AI** — build this as an internal testing tool (not a customer feature): generate phishing-pattern variants and run them against your own pipeline to find blind spots.
3. **Model governance** — track accuracy/precision/recall/drift per model version over time, require human approval before any retrained model goes live.

### Phase 11 — Hardening for Real Deployment
1. Move all secrets out of `.env` files into Vault (or at minimum Docker secrets) before anything touches real data.
2. Set up immutable audit logging for every decision and every auto-remediation action.
3. Load-test the pipeline, confirm Celery workers scale horizontally under volume.
4. Write and test your fail-open/fail-closed behavior explicitly — kill the service mid-test and confirm it behaves the way you decided in Phase 5.
5. Set up TLS everywhere, lock down the admin dashboard behind proper auth + rate limiting.
6. If you intend to pitch this to a real company eventually, start reading up on what SOC 2 / ISO 27001 readiness actually requires — you don't need certification to build the project, but designing with it in mind now saves a rebuild later.

### Phase 12 — Stretch Goals (only after everything above works end to end)
1. Playwright-based rendering for CAPTCHA-cloaked URL inspection.
2. CAPEv2 sandbox detonation for attachments that pass static checks but look suspicious.
3. Sign-in log correlation (Entra ID / Okta System Log) for basic AiTM/session-anomaly detection.

---

## 6. Suggested Folder Structure

```
guardian-ai/
│
├── gateway/              # Postfix + milter config
├── connectors/           # M365 Graph API + Gmail API pollers
├── backend/
│   ├── api/
│   ├── auth/
│   ├── email/            # shared parser used by both ingestion paths
│   ├── detection/
│   ├── behavior/         # BEC/relationship-graph module
│   ├── risk/             # single consolidated fusion + decision engine
│   ├── intelligence/     # domain age, threat-intel feed clients
│   ├── quarantine/
│   ├── campaigns/
│   ├── fraud_dna/
│   ├── redirect/         # URL rewriting + click-time re-check service
│   ├── remediation/      # auto-remediation hooks
│   ├── governance/
│   └── audit/
│
├── ai/
│   ├── phishing/          # XLM-R
│   ├── url/                # TF-IDF + LR
│   ├── credentials/        # regex + entropy
│   ├── image/               # OCR + QR
│   ├── malware/              # ClamAV/YARA/pefile
│   ├── behavior/               # Isolation Forest
│   └── fusion/                   # XGBoost calibrator
│
├── intelligence/
│   ├── fraud_dna/
│   ├── campaign_correlation/
│   ├── honeypot/
│   └── red_team/            # internal QA tool only
│
├── frontend/
│   ├── dashboard/
│   ├── threats/
│   ├── quarantine/
│   ├── campaigns/
│   └── fraud-dna/
│
├── database/               # migrations
├── models/                 # trained model artifacts
├── tests/
└── docker/
```

---

## 7. Suggested Team Role Split (adjust to your actual team size)

| Role | Owns |
|---|---|
| Backend/Gateway lead | Ingestion (SMTP + API), parser, API layer, auth |
| ML lead | XLM-R, URL model, behavioral Isolation Forest, XGBoost fusion |
| Security engineer | Malware scanning, SPF/DKIM/DMARC, threat-intel integration, sandbox (stretch) |
| Full-stack/frontend | React dashboard, quarantine review UI |
| Infra/DevOps | Docker Compose, CI/CD, secrets management, deployment, monitoring |

---

## 8. What "Done for v1" Actually Means

Don't try to ship every phase before demoing or pitching this. A credible, working v1 is: Phases 0–6 fully working end to end (ingestion → detectors → fusion → decision → Fraud DNA/campaigns → dashboard), plus Phase 7 (URL rewriting) since it's a strong, relatively cheap differentiator. Phases 8 and 10–12 are what you talk about as roadmap in a pitch, not what you need working on day one.
