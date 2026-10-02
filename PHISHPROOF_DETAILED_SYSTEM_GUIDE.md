# PhishProof — Detailed System Explanation Guide

**Product:** PhishProof (SIH pitch name)  
**Engine / repo:** Guardian AI (`SMTP_NEW_PROJECT`)  
**Audience:** Team study, judges, technical cross-questioning  
**Companion specs:** `PHISHPROOF_COMPLETE_FINAL.md`, `PHISHPROOF_SIH_PLAN.md`

> **Language rule used everywhere in this document**  
> Fusion score = **evidence consistency**, never “94% probability malicious.”  
> Origin = **probable originating infrastructure**, never “attacker city / GPS.”  
> Device-code / TOAD = **heuristics**. OAuth / AiTM = **roadmap / mock**, not live.

---

## Table of contents

1. [What the whole system is](#1-what-the-whole-system-is)
2. [Keyword glossary (every important term)](#2-keyword-glossary-every-important-term)
3. [End-to-end flow](#3-end-to-end-flow)
4. [Infrastructure systems](#4-infrastructure-systems)
5. [Ingestion & parsing systems](#5-ingestion--parsing-systems)
6. [Detection systems (every detector)](#6-detection-systems-every-detector)
7. [ML models (detailed + alternatives)](#7-ml-models-detailed--alternatives)
8. [Risk, fusion & decision ladder](#8-risk-fusion--decision-ladder)
9. [Privacy, vault & evidence](#9-privacy-vault--evidence)
10. [Cases, campaigns, map & forensic report](#10-cases-campaigns-map--forensic-report)
11. [Frontends & APIs](#11-frontends--apis)
12. [How PhishProof compares to real-world systems](#12-how-phishproof-compares-to-real-world-systems)
13. [What is parked / not claimed](#13-what-is-parked--not-claimed)
14. [Technical cross-questioning bank (by system)](#14-technical-cross-questioning-bank-by-system)
15. [Demo fixtures map](#15-demo-fixtures-map)

---

## 1. What the whole system is

PhishProof is a **Cyber Cell forensic intelligence workbench** built on a live **SMTP security gateway**.

Traditional tools ask: *Is this email malicious?*

PhishProof asks five questions:

1. What **evidence** says this mail is suspicious, and how strong is each signal?
2. Do independent signals **agree**, or **conflict**?
3. Where is the **probable originating infrastructure** (not the attacker’s home)?
4. Is this part of a **campaign** already seen in other complaints?
5. What **masked, court-oriented evidence package** does the investigator need — without storing victim bank secrets?

**One-line USP**

> PhishProof does not only classify mail — it explains evidence, traces infrastructure honestly, correlates campaigns with privacy-preserving fingerprints, protects victim PII, and knows when it should not trust its own verdict — on a live SMTP path.

---

## 2. Keyword glossary (every important term)

| Keyword | Plain meaning | Role in PhishProof | Where used |
|---|---|---|---|
| **SMTP** | Simple Mail Transfer Protocol — how mail servers exchange mail | Live demo ingress path | Postfix `:2525` / submission `:2587` |
| **Postfix** | Open-source mail transfer agent (MTA) | Accepts mail, hands to milter | `gateway/postfix/`, Docker `postfix` |
| **Milter** | Mail filter API; plugin that inspects mail during SMTP | Sends raw mail to API; can REJECT on BLOCK/HARD_BLOCK | `gateway/milter/guardian_milter.py` |
| **FastAPI** | Python web framework | REST API for ingest, SOC, mailbox, lab, health | `backend/main.py` |
| **PostgreSQL** | Relational database | Stores emails (redacted), scores, cases, campaigns, custody | Docker `postgres` |
| **Redis** | In-memory store / broker | Celery broker; dedup markers; short-lived coordination | Docker `redis` |
| **Celery** | Distributed task queue | Background jobs; retention beat | `backend/workers/` |
| **Docker Compose** | Multi-container orchestration | Runs entire stack locally for demo | `docker-compose.yml` |
| **JWT** | JSON Web Token | Login session for SOC / mail / lab | Auth routes |
| **RBAC** | Role-based access control | `user` / `viewer` / `analyst` / `admin` | `require_roles(...)` |
| **MIME** | Multipurpose Internet Mail Extensions — structure of email | Correct parse of HTML, attachments, multipart | `backend/email/parser.py` |
| **`.eml`** | Saved raw email file | SOC upload path for judges without SMTP clients | `POST /api/v1/soc/upload-eml` |
| **SHA-256** | Cryptographic hash | Evidence ID / dedup fingerprint of content | Pipeline + cases |
| **SPF** | Sender Policy Framework — did this IP may send for the domain? | Auth signal from Authentication-Results | `auth_checks.py` |
| **DKIM** | DomainKeys Identified Mail — cryptographic body/header signature | Auth signal | `auth_checks.py` |
| **DMARC** | Domain-based Message Authentication — policy + alignment | Auth + alignment signal | `auth_checks.py` |
| **Authentication-Results** | Header written by receiving MTA after SPF/DKIM/DMARC checks | **Source of truth** for auth (not inventing pass/fail) | `auth_checks.py` |
| **ARC** | Authenticated Received Chain — preserves auth across forwards | Secondary auth source when present | `auth_checks.py` |
| **Return-Path** | Envelope sender used for SPF | Used carefully for SPF domain context | `auth_checks.py` |
| **Received** | Hop-by-hop relay headers | Earliest **reliable public** IP for origin | `relay.py`, `origin.py` |
| **GeoLite2** | MaxMind offline geo/ASN database | City/ASN for infra hop (not attacker GPS) | `data/geoip/` |
| **ASN / ASO** | Autonomous System Number / Organisation | “DigitalOcean AS14061” style infra label | Origin evidence |
| **CGNAT** | Carrier-grade NAT private ranges | Filtered so we don’t treat them as public origin | `relay.py` |
| **WHOIS cache** | Offline JSON of domain age/registrar for demo domains | Young-domain signal without live WHOIS | `data/intel/whois_cache.json` |
| **Detector** | One independent evidence module | Votes a `raw_score` + `verdict` + explanation | `detection/engine.py` |
| **raw_score** | 0.0–1.0 strength from one detector | Input to weighted fusion | Every detector |
| **verdict** | Per-detector label (`clean` / `suspicious` / `malicious` / `not_applicable`) | Explains that detector’s view | SOC detail cards |
| **Fusion** | Combining detector scores | Weighted mean → fused risk 0–100 | `risk/engine.py` |
| **Variance / agreement** | How much detectors disagree | High variance → `UNCERTAIN` / `HUMAN_REVIEW` | `compute_confidence` |
| **CONFIDENT / UNCERTAIN** | Confidence **state**, not probability % | Drives review queues | Decision + UI |
| **Decision ladder** | PASS → SOFT_PASS → HUMAN_REVIEW → QUARANTINE → BLOCK → HARD_BLOCK | Operational outcome | `decide()` |
| **Booster** | Rule that escalates risk after fusion | e.g. strong URL + impersonation | `risk/engine.py` |
| **Heuristic** | Hand-written rule, not a trained ML model | Fallback + lure/TOAD/impersonation | Multiple modules |
| **XLM-R** | XLM-RoBERTa transformer for text phishing | Body/subject language | `models/email/` |
| **XGBoost** | Gradient-boosted trees | URL model (`url-xgb-v1`) | `models/url/v1/` |
| **Random Forest / calibrated RF** | Ensemble of trees (PDF v3 card/API) | PDF structural malware | `models/PDF_v3/` |
| **Office model** | Tree model on VBA/macro features | Macro malware in Office docs | `models/doc/` |
| **Feature extraction** | Turning raw bytes/URL into numeric vector | Feeds PDF/Office/URL models | `attachment_features.py`, URL extractor |
| **TOAD** | Telephone-Oriented Attack Delivery — “call this number” | Lure heuristic → often QUARANTINE | `signals.py` / lure |
| **Device-code phishing** | Abuse of OAuth device login codes | Heuristic lure text patterns | Heuristics (not Graph API) |
| **ATO** | Account Takeover | Trusted sender behaves abnormally vs baseline | `ato_baseline` |
| **Impersonation** | Display-name / lookalike domain tricks | Levenshtein + brand-in-unofficial-domain | Impersonation detector |
| **Homograph** | Lookalike Unicode characters (раypal vs paypal) | Soft impersonation signal | Impersonation |
| **Recon pixel** | Tiny tracking image | Privacy / recon signal | `recon_pixel` |
| **SVG / ICS** | Vector image / calendar invite abuse | Attachment/content lure channel | `svg_ics` |
| **Quishing** | QR-code phishing | URL from QR/alt → URL pipeline | `image_qr` + Case 3 |
| **Redaction** | Replace secrets with tokens | `[OTP]`, `[ACCT_LAST4]`, etc. | `privacy/redact.py` |
| **HMAC token** | Keyed hash of a secret | Campaign match **without storing digits** | Privacy + `campaign_keys` |
| **Vault** | Encrypted raw mail blob | Preserve for FIR; unlock logged | `privacy/vault.py` |
| **Custody** | Audit trail of evidence actions | exported / preserved / unlocked | Cases API |
| **Campaign** | Cluster of related complaints | Shared domain / IP / HMAC keys | `cases/service.py` |
| **Case / case_ref** | Complaint record id | e.g. `PHISH-MH-2026-…` | Intake |
| **Forensic report** | Written PS-style assessment | Officer-readable narrative | `/report`, SOC button |
| **FIR pack** | First Information Report oriented notes | Draft package for Cyber Cell story | Cases API |
| **Leaflet** | JS map library | Infra geo pins | SOC Map tab |
| **Model Lab** | Standalone scan APIs/UI | Test XLM-R / Office / PDF / URL without SMTP | Lab tab + `/api/v1/lab/*` |
| **Dual-control** | Two roles needed to unlock secrets | Spec goal; **prototype logs custody, not full dual role** | Be honest in viva |
| **Parked** | Intentionally deferred post-SIH | ClamAV, live WHOIS, Force Graph UI, etc. | Plan §Parked |

---

## 3. End-to-end flow

```text
SMTP (Postfix) or SOC Upload .eml
        │
        ▼
   Milter / API ingest  ──►  Parse MIME in RAM
        │
        ▼
   Privacy scan (find secrets) ──► analyse full content in memory
        │
        ▼
   Detectors (auth, XLM-R, URL, creds, QR, malware heuristic,
              PDF/Office ML, origin, impersonation, pixel, SVG/ICS,
              lure/TOAD, ATO)
        │
        ▼
   Risk fusion (weighted scores) + variance confidence + boosters
        │
        ▼
   Decision: PASS / SOFT_PASS / HUMAN_REVIEW / QUARANTINE / BLOCK / HARD_BLOCK
        │
        ├─► Persist tokens + scores + evidence hash (not cleartext OTP/PAN)
        ├─► Attach campaign keys (domain / IP / HMAC)
        ├─► Optional vault ciphertext
        └─► Milter REJECT if BLOCK / HARD_BLOCK
        │
        ▼
   SOC: queues, map, campaigns, intake, Preserve, Forensic report
```

**Key code paths**

| Step | Path |
|---|---|
| Pipeline | `backend/email/pipeline.py` |
| Parse | `backend/email/parser.py` |
| Detectors | `backend/detection/engine.py` → `run_all_detectors` |
| Risk | `backend/risk/engine.py` |
| Privacy | `backend/privacy/redact.py`, `vault.py` |
| Campaigns / report | `backend/cases/service.py` |

---

## 4. Infrastructure systems

### 4.1 Docker Compose stack

| Service | Port / role | Why it exists |
|---|---|---|
| `api` | `:8000` FastAPI | Brain of the system |
| `worker` | Celery (+ beat) | Retention / async tasks |
| `postgres` | `:5432` | Durable state |
| `redis` | `:6379` | Broker + markers |
| `postfix` | `:2525`, `:2587` | Real SMTP gateway |
| `milter` | internal `8891` | Inspection + reject |
| `dashboard` | `:5174` | SOC / PhishProof UI |
| `mail-client` | `:5173` | End-user webmail demo |

**Why better for a prototype than “Flask + upload only”**  
You can show **policy at the mail edge** (REJECT) and **analyst workflow** in one compose file — closer to real Secure Email Gateway (SEG) architecture.

### 4.2 Postfix + milter

**Role:** Act as the organisation’s inbound/outbound checkpoint.  
**Better than pure API demos:** Judges see mail *enforcement*, not only scoring.  
**Cross-q angle:** Milter calls ingest API with key; on BLOCK/HARD_BLOCK returns reject.

### 4.3 FastAPI + JWT + RBAC

**Role:** Secure programmatic surface for mail client, SOC, lab, ingest.  
**Roles:** mailbox user vs analyst vs admin — separates victim UX from Cyber Cell UX.

### 4.4 PostgreSQL + Redis + Celery

**Postgres:** emails, detector rows, decisions, cases, campaigns, custody, vault metadata.  
**Redis:** Celery + dedup markers (marker after successful commit — integrity detail).  
**Celery beat:** retention enforcement hourly — privacy lifecycle, not only detection.

### 4.5 Health / readiness

`GET /health/ready` checks DB, Redis, and presence of email / PDF / Office / URL model artifacts.  
**Demo use:** Prove models are on disk before pitching.

---

## 5. Ingestion & parsing systems

### 5.1 Ingest paths

| Path | Entry | Same engine? |
|---|---|---|
| SMTP | milter → ingest | Yes |
| SOC upload | `upload-eml` | Yes |
| Mail compose | mailbox API → gateway | Yes (outbound still analysed) |

### 5.2 MIME parser (`parser.py`)

**Role:** Extract sender, recipients, subject, plain/HTML, URLs (href + bare), attachments, headers.  
**Details that matter in viva:**
- HTML → plain for NLP
- Inline images
- Single-part attachments
- Reject Outlook `.msg` (unsupported container)
- Scheme-less / bare URLs for phishing that omits `https://`

**Why it matters:** Bad parse = silent false negatives. Many student demos only regex the body string.

### 5.3 Evidence hash (SHA-256)

**Role:** Stable evidence ID + dedup.  
**Better than storing full raw forever in cleartext:** hash identifies the artifact; vault holds ciphertext only when preserved.

---

## 6. Detection systems (every detector)

All detectors return a common shape: `detector_name`, `raw_score`, `verdict`, `explanation`, `evidence`, `model_version`.

Orchestrator: `run_all_detectors()` in `backend/detection/engine.py`.

### 6.1 `sender_auth` — SPF / DKIM / DMARC

| | |
|---|---|
| **Type** | Protocol / header analysis (not ML) |
| **Where** | `detection/auth_checks.py` |
| **Role** | Did the receiving stack attest auth? Alignment? |
| **Important honesty** | Reads **Authentication-Results / ARC**, does not invent results. Auth **pass does not erase** phishing/ATO risk. |
| **Better than naive “SPF fail = phish”** | Real attacks often pass SPF on lookalike or compromised domains; ATO mail can be fully authenticated. |

### 6.2 `xlm_r_phishing` — text phishing ML

| | |
|---|---|
| **Type** | Transformer classifier (XLM-RoBERTa) |
| **Where** | `ml_runtime.py` + `models/email/` |
| **Role** | Semantic phishing language in subject/body |
| **Fallback** | Heuristic keyword text if model unloadable |
| **Strength** | Catches urgency / credential lure language across languages |
| **Limit** | Can miss ATO “normal sounding” gift/wire mail (Case 5) — by design other detectors catch that |

### 6.3 `url_model` — URL risk ML + heuristics

| | |
|---|---|
| **Type** | XGBoost (`url-xgb-v1`) + lexical heuristics |
| **Where** | `url_ml.py`, `url_heuristics.py`, `models/url/v1/` |
| **Role** | Score links without live browsing (safe, offline, fast) |
| **Policy** | Soft thresholds 0.35 / 0.70; often `max(ML, heuristics)` so novel lookalikes don’t slip |
| **Better than VirusTotal-only** | Works offline; no dependency on venue internet for core score |

### 6.4 `credential_detector`

| | |
|---|---|
| **Type** | Regex + entropy heuristics |
| **Role** | Detect OTP / PAN / card / password-like / keys in content |
| **Coupled with privacy** | Findings drive **redaction tokens**, not training on secrets |
| **Direction-aware** | Outbound secret leak can be treated severely |

### 6.5 `image_qr` — quishing path

| | |
|---|---|
| **Type** | QR/URL enrichment → same URL pipeline |
| **Honesty for demo** | Full bitmap decode needs pyzbar/OpenCV (not in image). Case 3 works via HTML/alt URL path. |
| **Role** | Don’t ignore QR as “invisible” channel when URL is obtainable |

### 6.6 `malware_scan` — heuristic malware

| | |
|---|---|
| **Type** | Signature/heuristic (EICAR / dangerous types) |
| **Honesty** | **ClamAV / YARA parked** — do not claim AV engine |
| **Role** | Basic executable/dangerous attachment tripwire |

### 6.7 `doc_attachment_threat` — PDF v3 + Office ML

| | |
|---|---|
| **Type** | Structural ML on attachments |
| **Role** | Malicious PDF JS/OpenAction/etc.; Office macro malice |
| **Fallback** | Structural heuristics if models fail |
| **Better than extension-only blocklists** | Looks at **behavioural structure**, not just `.pdf` |

### 6.8 `origin_infra` — infrastructure origin

| | |
|---|---|
| **Type** | Received parsing + GeoLite2 + intel lists + WHOIS **cache** |
| **Role** | Probable originating **infrastructure** class (cloud/VPN/TOR/hosting) |
| **Language** | Never “we found the criminal in Frankfurt” |
| **Better than scare-map demos** | Forensically honest; matches how IR teams talk |

### 6.9 `impersonation`

| | |
|---|---|
| **Type** | String distance / brand / Reply-To mismatch / homograph |
| **Role** | “Bank of Baroda” from unofficial domain, lookalike hosts |
| **Why critical** | Case 2-style bank lookalikes |

### 6.10 `recon_pixel`

| | |
|---|---|
| **Type** | Heuristic on tiny tracking images |
| **Role** | Recon / open-tracking pattern often used in phishing kits |

### 6.11 `svg_ics`

| | |
|---|---|
| **Type** | Heuristic on SVG/ICS abuse patterns |
| **Role** | Alternate delivery channels for links/scripts/calendar lures |

### 6.12 `lure_heuristics` — TOAD / device-code / invoice drift

| | |
|---|---|
| **Type** | NLP/regex heuristics (**not ML**) |
| **Role** | Callback scams, device-code language, invoice anomalies |
| **Decision effect** | Often elevates to QUARANTINE without claiming Graph/OAuth telemetry |

### 6.13 `ato_baseline` — account takeover

| | |
|---|---|
| **Type** | Baseline comparison vs pre-seeded “normal” sender behaviour |
| **Role** | Catch compromised legitimate mailboxes that pass auth + look clean to NLP |
| **USP overlap** | Most spam filters under-invest here; Cyber Cell sees ATO wire fraud |

---

## 7. ML models (detailed + alternatives)

### 7.1 Summary table

| Model | Artifact | Algorithm | Input | Output | Reported metrics | Live? |
|---|---|---|---|---|---|---|
| **XLM-R v1** | `models/email/` (`model.safetensors`) | XLM-RoBERTa sequence classifier | Subject + body text | Phishing score | Smoke-tested; **no full formal card** in-repo | Yes |
| **URL url-xgb-v1** | `models/url/v1/url_model.json` | XGBoost binary logistic | 37 lexical/structural URL features | p(malicious) | ROC-AUC **0.9469**, ~**89.7%** accuracy; FPR~1% @ 0.9062 | Yes |
| **PDF v3** | `models/PDF_v3/pdf_malware_model.joblib` | Calibrated tree ensemble (RF family per lab card) | PDF structural features | p(malicious) | Recall ~**89.2%**, FPR ~**0.71%** | Yes |
| **Office v1** | `models/doc/office_malware_rf.joblib` | Tree ensemble (card: XGBoost-style metrics) | ~40 macro/VBA features | p(malicious) | ROC-AUC ~**99.18%**, acc ~**83.4%**, FPR ~**4.4%** | Yes |

> Large `.safetensors` / `.joblib` weights are **gitignored**; they must exist on the demo machine / volume mounts.

### 7.2 XLM-RoBERTa — why this choice

**Why it fits**
- Multilingual (India: EN/HI mixed mail)
- Contextual — beats bag-of-words on paraphrased lures
- Strong semantic detector in an **ensemble**, not the sole judge

**Compared to alternatives**

| Alternative | Pros | Cons vs XLM-R here |
|---|---|---|
| Keyword / TF-IDF + LogReg | Tiny, fast | Brittle; easy evasion |
| LSTM / older RNN | Sequential | Weaker transfer; heavier train ops |
| DistilBERT (English-only) | Faster | Weaker multilingual coverage |
| GPT API classifiers | Strong zero-shot | Needs internet, cost, privacy leak of victim mail |
| SpamAssassin rules only | Transparent | Misses modern semantic phishing |

**Best for our solution because:** offline, privacy-safe inference on full text in RAM, multilingual, pairs with variance fusion when it disagrees with URL/ATO.

### 7.3 URL XGBoost (`url-xgb-v1`) — why this choice

**Why it fits**
- CPU-only, millisecond scoring — safe on SMTP path
- No fetching the phishing site (no drive-by risk in scanner)
- Strong tabular performance on lexical features
- Carded metrics for judge credibility

**Compared to alternatives**

| Alternative | Pros | Cons vs url-xgb-v1 |
|---|---|---|
| Blacklists / Google Safe Browsing | High precision on known bad | Blind to fresh domains; needs live API |
| VirusTotal URL | Rich intel | Rate limits; not offline; not a gateway |
| Deep URL neural nets | Can learn complex patterns | Heavier; often need more features/crawl |
| Heuristics only | Interpretable | Misses subtle patterns ML catches |
| TF-IDF on raw URL string | Simple | Weaker than engineered lexical + XGB |

**Best for our solution because:** offline SEG constraint + explainable features + heuristic override for SIH-hard cases (odd TLD, lookalike hosts).

### 7.4 PDF v3 — why this choice

**Why it fits**
- Structural features (JS, OpenAction, encrypt, streams…) match real PDF malware tradecraft
- Bias-prone size/metadata features excluded (per model card)
- Calibrated thresholds (suspicious vs malicious)

**Compared to alternatives**

| Alternative | Pros | Cons vs PDF v3 |
|---|---|---|
| ClamAV signatures | Great known malware | Parked; weak on novel structure |
| YARA rules | Flexible | Manual; parked |
| Full sandbox (CAPEv2) | Deep detonation | Too heavy for SIH SMTP latency |
| “Block all PDFs” | Simple | Breaks business mail |

**Best for our solution because:** fast static ML aligned with gateway latency; complements (not replaces) future ClamAV.

### 7.5 Office macro model — why this choice

**Why it fits**
- Macro malware still common in invoice phishing
- Features map to VBA abuse (`AutoOpen`, `Shell`, `CreateObject`, …)
- Skips scoring when no VBA project (reduces false drama)

**Compared to alternatives**

| Alternative | Pros | Cons |
|---|---|---|
| oletools rules only | Transparent | Less calibrated ranking |
| AMSI / Defender cloud | Strong on endpoints | Not in our mail gateway demo |
| Deep learning on raw OLE | Researchy | Harder to explain / ship offline |

**Best for our solution because:** explainable macro indicators + calibrated score into fusion.

### 7.6 What is *not* an ML model (do not mis-label)

- Variance fusion / weighted risk  
- SPF/DKIM/DMARC  
- Impersonation / TOAD / recon pixel heuristics  
- GeoLite2 / WHOIS cache  
- Campaign key merge  

---

## 8. Risk, fusion & decision ladder

### 8.1 Weighted fusion

Approximate weights (`backend/risk/engine.py`):

| Detector | Weight |
|---|---|
| sender_auth | 0.16 |
| url_model | 0.15 |
| xlm_r_phishing | 0.15 |
| credential_detector | 0.10 |
| malware_scan | 0.10 |
| doc_attachment_threat | 0.10 |
| impersonation | 0.10 |
| ato_baseline | 0.09 |
| lure_heuristics | 0.07 |
| svg_ics | 0.07 |
| recon_pixel | 0.06 |
| origin_infra | 0.05 |

`fused_risk ≈ 100 × weighted_mean(raw_scores)`.

### 8.2 Confidence = variance

- Independent detectors’ scores → population variance  
- Low variance → `CONFIDENT`  
- High variance without strong content agreement → `UNCERTAIN` → often `HUMAN_REVIEW`  
- Some high payload scores can still force confidence / hard decisions (boosters / overrides)

### 8.3 Decision ladder (operational meaning)

| Decision | Meaning for Cyber Cell / mail |
|---|---|
| **PASS** | Deliver / low concern |
| **SOFT_PASS** | Deliver with caution / watch |
| **HUMAN_REVIEW** | Analyst must look (conflict or ATO-style drift) |
| **QUARANTINE** | Hold from user inbox (e.g. TOAD) |
| **BLOCK** | Block delivery |
| **HARD_BLOCK** | Strongest block + milter reject |

**Why better than binary phish/not-phish:** Matches real SOC triage and reduces “cry wolf” hard blocks on callback scams vs malware URLs.

---

## 9. Privacy, vault & evidence

### 9.1 Privacy Manager (`redact.py`)

**Finds & tokenises:** OTP, last-4, PAN, Aadhaar, cards, IFSC-ish patterns, AWS keys, JWT, private keys, etc.  
**Persists:** tokens + flags — **not** digits.  
**Reports:** masked forensic text.

**Why better than typical “save email for ML training” demos:** Aligns with Indian cybercrime complaint ethics and DPDP-minded design.

### 9.2 HMAC campaign tokens

Sensitive values → HMAC with dedicated `HMAC_SECRET` (not JWT secret) → campaign keys like `hmac:…`.  
**Effect:** Same last-4 across victims can link a campaign **without a database of bank digits**.

### 9.3 Vault (`vault.py`)

Fernet encryption with dedicated `VAULT_SECRET`.  
**Preserve** stores ciphertext; **Unlock** returns raw with custody log + warning.  
**Honest limit:** Full dual-control IO role gate is incomplete — custody exists; two-person rule is post-SIH polish.

### 9.4 Custody + retention

Every export/preserve/unlock is an auditable event.  
Celery beat enforces retention windows — evidence lifecycle, not infinite cleartext.

---

## 10. Cases, campaigns, map & forensic report

### 10.1 Complaint intake & cases

Analyst enters victim context (mobile tokenised, amount, bank, district) → `case_ref` like `PHISH-MH-YEAR-…`.  
**Role:** Connect technical email object to **police complaint workflow**.

### 10.2 Campaign linking (“fingerprinting”, not DNA-ML)

**Keys:** `domain:…`, `ip:…`, `hmac:…`  
**Merge rule:** Any overlapping key → same campaign cluster.  
**UI:** Map / campaigns list (Force Graph UI **not** built — correlation is).  

**Compared to “cosine similarity of body text”:** More privacy-safe and infra-grounded for Cyber Cell “same gang?” questions.

### 10.3 Leaflet map

Pins from GeoLite2 of origin hop.  
**Must say:** infrastructure location estimate; needs internet for tiles in demo venue.

### 10.4 Forensic report

`forensic_assessment_text()` + `GET /api/v1/soc/emails/{id}/report`  
SOC primary button **Forensic report**.  
**Role:** Officer-readable narrative: findings, infra, campaign note, recommended actions — masked.

### 10.5 FIR / ISP note drafts

Case layer can emit FIR-oriented / ISP notice style packs for the pitch story (templates + evidence refs).

---

## 11. Frontends & APIs

### 11.1 SOC Dashboard (`:5174`)

Threats / High / Uncertain queues, upload `.eml`, alerts banner, cases, map/campaigns, lab, forensic report, preserve/unlock, intake, i18n **EN / HI / MR**.

### 11.2 Mail Client (`:5173`)

Inbox / quarantine / compose — shows **user-visible consequence** of gateway decisions.

### 11.3 Model Lab APIs

`/api/v1/lab/scan/text|office|pdf` (+ URL status) for component demos without SMTP.

### 11.4 Core API groups

| Prefix | Purpose |
|---|---|
| `/api/v1/auth` | Login/register/me |
| `/api/v1/ingest` | Raw ingest |
| `/api/v1/mailbox` | User mail |
| `/api/v1/soc` | Analyst queues, upload, release/block |
| `/api/v1/soc` (cases router) | Intake, report, FIR, preserve, unlock, campaigns, map |
| `/api/v1/lab` | Model lab |
| `/health`, `/health/ready` | Liveness / model readiness |

---

## 12. How PhishProof compares to real-world systems

### 12.1 Comparison matrix

| Capability | Gmail / Outlook defender | Secure Email Gateway (Proofpoint, Mimecast, Cisco) | Open-source (SpamAssassin, Rspamd) | VirusTotal / URLScan | **PhishProof (this prototype)** |
|---|---|---|---|---|---|
| SMTP inline enforce | Vendor cloud | Yes | Possible | No | **Yes (Postfix+milter)** |
| Multi-ML content | Opaque vendor ML | Yes (proprietary) | Mostly rules | N/A | **Yes (4 local models)** |
| Uncertainty / human review | Limited user labels | SOC products vary | Low | N/A | **First-class HUMAN_REVIEW + variance** |
| Infra-honest origin map | Rare / marketing geo | Some threat intel | Rare | Passive | **Explicit non-attacker-GPS language** |
| Victim PII redaction + vault | Not for police intake | DLP differs | No | No | **Cyber Cell–oriented privacy manager** |
| Campaign link without storing secrets | Vendor clusters | Yes (closed) | Weak | Manual | **HMAC + domain/IP keys** |
| Written forensic report for FIR story | No | IR tools separate | No | Manual | **Built-in masked report** |
| Offline / on-prem demo | No | Expensive appliance | Yes | Needs net | **Docker on-prem friendly** |
| Production scale / SLA | Huge | Huge | DIY | API | **Prototype — not production SEG** |
| Live VT / sandbox / ClamAV | Vendor | Yes | Optional | Core | **Parked** |
| Dual-control evidence unlock | Compliance products | Yes | No | No | **Partial (custody; not full dual-control)** |

### 12.2 What we are *better at* (honestly, for SIH / Cyber Cell brief)

1. **Explainability + disagreement handling** vs black-box “phishing %”.  
2. **Privacy-first complaint evidence** vs saving raw OTP/PAN.  
3. **Forensic narrative + case/campaign** vs detection-only demos.  
4. **Honest origin semantics** vs fake “track the hacker” maps.  
5. **Full local stack** judges can run without buying Proofpoint.

### 12.3 What production systems still beat us at

- Global telemetry & reputation networks  
- Hardened scale, TLS edge, abuse desks  
- Sandboxed detonation, full AV/YARA stacks  
- Mature dual-control / legal hold  
- Enterprise admin UX and SLAs  

**Pitch line:** *We are not replacing Proofpoint in one hackathon — we are the open, India Cyber Cell–shaped forensic layer that commercial filters don’t ship.*

### 12.4 Comparison to typical SIH phishing projects

| Typical SIH project | PhishProof |
|---|---|
| Streamlit upload → one model % | Gateway + fusion + decisions |
| Accuracy table only | SOC + mail client + cases |
| Stores dataset emails with secrets | Redaction + vault |
| “Attacker in city X” | Infra hop disclaimer |
| No enforcement | Milter REJECT |

---

## 13. What is parked / not claimed

Do **not** tell judges these are live:

| Item | Status |
|---|---|
| ClamAV / YARA / pefile deep AV | Parked |
| Trained XGBoost **fusion** model | Parked (weighted+boosters live) |
| Live WHOIS / VirusTotal / SIEM | Parked (WHOIS **cache** live) |
| React Force Graph | Not built (campaign **list** live) |
| Nginx/TLS production edge | Parked |
| OAuth consent / AiTM detection | Mock / roadmap |
| True dual-control unlock | Partial |
| Real QR bitmap decode in Docker image | Limited (URL/alt path works) |
| Root `models/url/*` except `v1/` | Unused / parked |

---

## 14. Technical cross-questioning bank (by system)

### 14.1 Overall architecture

| Question | Strong answer |
|---|---|
| Walk one email SMTP → decision | Postfix → milter → ingest → parse RAM → detectors → fusion/variance/boosters → decision → DB tokens → milter reject if HARD_BLOCK/BLOCK |
| Why Docker Compose? | Reproducible on-prem demo: MTA+API+DB+UIs |
| Same engine for upload and SMTP? | Yes — `pipeline.ingest_and_analyze` |
| Where is business logic? | `backend/email/pipeline.py` + `detection/` + `risk/` |

### 14.2 Fusion & decisions

| Question | Strong answer |
|---|---|
| Is 92 a probability? | **No** — fused evidence score 0–100 |
| What is confidence? | Variance across independent detectors |
| Why HUMAN_REVIEW? | Disagreement or ATO-style cases where auto-block is wrong |
| Why not trained fusion XGBoost? | Parked; weighted+boosters are transparent for SIH |

### 14.3 Auth

| Question | Strong answer |
|---|---|
| Do you implement SPF checks yourself? | We consume Authentication-Results/ARC from the MTA path |
| Can pass auth still be phish? | **Yes** — lookalike domains & ATO |
| Do you down-score on auth pass? | Auth is a signal; it must not launder phishing content |

### 14.4 Models

| Question | Strong answer |
|---|---|
| Why XLM-R not GPT API? | Privacy, offline, latency, cost |
| URL model features? | 37 lexical/structural — no live crawl |
| PDF vs ClamAV? | Static structure ML now; ClamAV later |
| What if model missing? | Heuristic fallback; readiness endpoint shows gaps |
| XLM-R accuracy card? | Honest: real weights; formal holdout card thinner than URL/PDF — ensemble role matters |

### 14.5 Origin / map / WHOIS

| Question | Strong answer |
|---|---|
| Attacker in Frankfurt? | **No** — DigitalOcean infra hop estimate |
| Live WHOIS? | Cached JSON for demo domains |
| Private IP as origin? | Filtered; want earliest reliable public hop |

### 14.6 Privacy

| Question | Strong answer |
|---|---|
| Where is OTP stored? | Not in Postgres cleartext — tokenised |
| How campaign match last-4? | HMAC token overlap |
| Why separate HMAC/VAULT secrets? | Blast-radius separation from JWT |
| Dual control? | Custody logged; full two-person rule is future work |

### 14.7 Campaigns

| Question | Strong answer |
|---|---|
| DNA fingerprinting ML? | Infra/token key merge, not embedding DNA |
| Force Graph? | Correlation yes; fancy graph UI no |

### 14.8 QR / TOAD / OAuth

| Question | Strong answer |
|---|---|
| Decode QR pixels? | Demo path uses obtainable URL; full CV decode not in image |
| TOAD ML? | Heuristic lure |
| AiTM live? | **No** — roadmap |

### 14.9 Comparison / product

| Question | Strong answer |
|---|---|
| Why not just Gmail? | On-prem forensic + privacy + case/campaign for Cyber Cell |
| USP? | Evidence agreement + infra-honest origin + PII-safe campaign/report on live SMTP |
| Biggest limitation? | Pick one: dual-control / QR decode / no global reputation — and say post-SIH |

### 14.10 Trap questions (wrong vs right)

| Trap | Wrong | Right |
|---|---|---|
| “92% phishing” | Agree | “Fused risk 92; not calibrated probability” |
| “Show attacker GPS” | Point at city | “Infra class / ASN hop” |
| “Models not integrated” (old README) | Panic | “`/health/ready` all ok; README stale” |
| “You built Proofpoint” | Yes | “Cyber Cell forensic prototype on SEG pattern” |

---

## 15. Demo fixtures map

| File | Expected story | Typical decision |
|---|---|---|
| `fixtures/demo_eml/case1_clean.eml` | Benign baseline | PASS |
| `fixtures/demo_eml/case2_bank_lookalike.eml` | Impersonation + URL + tokens | HARD_BLOCK (masked `[ACCT_LAST4]`/`[OTP]`) |
| `fixtures/demo_eml/case3_qr_quishing.eml` | QR/URL channel | BLOCK or HARD_BLOCK |
| `fixtures/demo_eml/case4_toad_callback.eml` | Callback lure | QUARANTINE |
| `fixtures/demo_eml/case5_ato_trusted.eml` | Trusted mailbox drift | HUMAN_REVIEW |

**Pre-demo:** `docker compose ps` → `/health/ready` → upload five cases → Forensic report on Case 2 → Map pin → say the language rules out loud.

---

## Appendix A — Repo map (quick)

```text
backend/           API, detection, risk, privacy, workers
gateway/           Postfix + milter
frontend/dashboard SOC (PhishProof)
frontend/mail-client
models/email       XLM-R
models/url/v1      url-xgb-v1
models/PDF_v3      PDF malware
models/doc         Office malware
data/geoip         GeoLite2
data/intel         WHOIS cache, VPN/TOR/cloud, ATO baselines
fixtures/demo_eml  Five pitch cases
```

## Appendix B — Pitch close

PhishProof’s systems are not a pile of models. They are a **pipeline of evidence**:

**ingest → parse → multi-signal detect → disagree-aware decide → redact → link → report**

That full chain — especially **uncertainty**, **privacy**, and **infra-honest forensics** on a **live mail gateway** — is what makes this prototype distinct from both toy SIH classifiers and opaque commercial “phish %” filters.

---

*Document generated for team preparation. If code and this guide disagree, trust the running code + `PHISHPROOF_COMPLETE_FINAL.md`, then update this file.*
