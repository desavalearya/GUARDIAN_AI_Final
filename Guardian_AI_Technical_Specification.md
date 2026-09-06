# Guardian AI — Technical Specification (Companion to Final Build Plan)

**Purpose:** This is the document that closes the gaps left in the Final Build Plan — schema, interfaces, the confidence engine's actual logic, dataset sourcing, service architecture, and evaluation methodology. Read this alongside `Guardian_AI_Final_Build_Plan.md`, not instead of it. Nothing here is code — it's the specification your team codes against, so four people can build in parallel without guessing at each other's interfaces.

---

## 1. Database Schema

### 1.1 `emails` — every ingested message, one row per email
| Field | Type | Notes |
|---|---|---|
| email_id | UUID, primary key | Generated at ingestion |
| received_at | timestamp | When Guardian ingested it |
| sender_address | text | Raw From header address |
| sender_display_name | text | Display name, separate from address (spoofing signal) |
| recipient_address | text | |
| subject | text | |
| body_plain | text | Plain-text body |
| body_html | text | Raw HTML body, nullable |
| language_detected | text | ISO code or "hi-en-mixed" for Hinglish |
| ingestion_path | enum | "milter" or "rspamd" — record which path it came through |
| raw_headers | JSON/text blob | Full header dump for later forensics |
| status | enum | "processing", "scored", "decided" |

### 1.2 `email_urls` — every URL extracted from an email, one row per URL
| Field | Type | Notes |
|---|---|---|
| url_id | UUID, primary key | |
| email_id | UUID, foreign key → emails | |
| raw_url | text | As it appeared in the email |
| source | enum | "body_text", "qr_code", "image_ocr" — where it was extracted from |
| domain | text | Parsed out for domain-age/threat-intel lookups |

### 1.3 `email_attachments` — one row per attachment
| Field | Type | Notes |
|---|---|---|
| attachment_id | UUID, primary key | |
| email_id | UUID, foreign key → emails | |
| filename | text | |
| file_hash_sha256 | text | For repeat-file detection and threat-intel lookup |
| mime_type | text | |
| file_size_bytes | integer | |

### 1.4 `detector_results` — one row per detector, per email (this is the core interoperability table)
| Field | Type | Notes |
|---|---|---|
| result_id | UUID, primary key | |
| email_id | UUID, foreign key → emails | |
| detector_name | enum | "xlm_r_phishing", "url_model", "credential_detector", "image_qr", "malware_scan", "sender_auth" |
| raw_score | float, 0.0–1.0 | Detector's own confidence in its verdict, normalized |
| verdict | enum | "malicious", "suspicious", "clean", "not_applicable" |
| explanation | text | Human-readable reason (this feeds the dashboard's "why" view) |
| evidence | JSON | Detector-specific structured detail — e.g. which regex matched, which URL was flagged, which phrase triggered the phishing model |
| model_version | text | Which trained model version produced this (ties into §1.9) |
| processed_at | timestamp | |

**Why this table exists:** every detector, regardless of what it internally does, writes to this same table in this same shape. This is the single contract that lets four people build four detectors independently and have them snap together without a Phase 3 integration crisis.

### 1.5 `confidence_scores` — output of the fusion engine, one row per email
| Field | Type | Notes |
|---|---|---|
| email_id | UUID, foreign key → emails | |
| fused_risk_score | float, 0–100 | Final combined risk number |
| confidence_state | enum | "CONFIDENT" or "UNCERTAIN" |
| agreement_metric | float | The disagreement measure used to set confidence_state (see §3) |
| contributing_detectors | JSON | Snapshot of each detector's weighted contribution to the final score, for the dashboard breakdown |
| fusion_method_version | text | Which version of the fusion logic produced this |

### 1.6 `decisions` — final action taken, one row per email
| Field | Type | Notes |
|---|---|---|
| email_id | UUID, foreign key → emails | |
| decision | enum | "PASS", "SOFT_PASS", "QUARANTINE", "BLOCK", "HUMAN_REVIEW" |
| decided_at | timestamp | |
| analyst_override | boolean | True if a human changed the automated decision |
| analyst_id | UUID, nullable | Who overrode it, if applicable |
| analyst_notes | text, nullable | |

### 1.7 `fraud_dna` — one fingerprint record per confirmed malicious email
| Field | Type | Notes |
|---|---|---|
| fingerprint_id | UUID, primary key | |
| email_id | UUID, foreign key → emails | |
| sender_domains | text array | |
| urls | text array | |
| attachment_hashes | text array | |
| techniques_detected | text array | e.g. "urgency", "credential_harvesting", "qr_phishing" |
| fuzzy_hash | text | ssdeep or TLSH hash of the body |
| text_embedding | vector | sentence-transformers embedding, for similarity search |
| campaign_id | UUID, nullable, foreign key → campaigns | Set once clustered |
| created_at | timestamp | |

### 1.8 `campaigns` — a cluster of related fraud_dna records
| Field | Type | Notes |
|---|---|---|
| campaign_id | UUID, primary key | |
| first_seen | timestamp | |
| last_seen | timestamp | |
| attack_count | integer | Updated as new fingerprints join |
| growth_rate_flag | enum | "stable", "growing", "escalating" — Tier 2 escalation heuristic output |

### 1.9 `model_versions` — manual model registry (Tier 2, replaces automated governance)
| Field | Type | Notes |
|---|---|---|
| model_name | text | e.g. "xlm_r_phishing" |
| version | text | e.g. "v1.2-hinglish" |
| trained_at | timestamp | |
| eval_precision | float | |
| eval_recall | float | |
| eval_f1 | float | |
| eval_dataset_description | text | Which dataset/split this was evaluated on — critical for honest reporting |
| deployed | boolean | Is this the currently active version |

### 1.10 `threat_intel_lookups` (Tier 2 — only if Phase 8 is reached)
| Field | Type | Notes |
|---|---|---|
| url_id or attachment_id | UUID | |
| source | enum | "virustotal", "urlhaus", "whois_age" |
| result | JSON | Raw response, structured |
| looked_up_at | timestamp | |

---

## 2. API Contract — How Services Talk to Each Other

### 2.1 Parser → Detectors (the input every detector receives)
Every detector receives the same standardized "parsed email" object, regardless of which detector it is. This object contains: `email_id`, `sender_address`, `sender_display_name`, `subject`, `body_plain`, `body_html`, `language_detected`, a list of extracted URL objects (each with `url_id`, `raw_url`, `domain`, `source`), a list of extracted image objects (each with `image_id`, `raw_bytes_reference`, i.e. a storage path, not the raw bytes themselves, to keep payloads light), and a list of attachment objects (each with `attachment_id`, `filename`, `file_hash_sha256`, `storage_reference`).

**Rule:** a detector only reads the fields relevant to it. The URL model never touches `body_plain`. The phishing model never touches attachments. This keeps each detector genuinely independent, which matters for the confidence engine's core assumption (§3) that detector errors are uncorrelated.

### 2.2 Detectors → `detector_results` table (the output every detector produces)
Every detector, regardless of internal logic, must produce exactly these fields, matching §1.4: `email_id`, `detector_name`, `raw_score` (float 0.0–1.0, where 1.0 = maximally malicious — **this normalization is mandatory**, a detector cannot return a raw log-odds or an unbounded number), `verdict` (one of the four enum values), `explanation` (a single human-readable sentence — this is not optional, it's what makes the dashboard's "why" view possible), and `evidence` (a structured JSON blob specific to that detector — e.g. the URL model includes which lexical features fired, the credential detector includes which regex pattern and entropy value triggered it).

**Rule:** if a detector cannot produce a score for a given email (e.g. the image/QR detector on an email with no images), it writes a `detector_results` row with `verdict = "not_applicable"` rather than omitting the row — this keeps the confidence engine's input complete and explicit rather than silently missing data.

### 2.3 Detector Results → Confidence/Fusion Engine (the input the fusion engine receives)
The fusion engine queries all `detector_results` rows for a given `email_id`, receiving a list of `(detector_name, raw_score, verdict)` tuples — one entry per detector that ran (with `not_applicable` entries excluded from the fusion math but logged for audit). This is the only input the fusion engine needs; it must not reach back into raw email content — this boundary is what keeps the fusion engine a pure aggregation layer, testable independently of the detectors.

### 2.4 Fusion Engine → `confidence_scores` and Decision Engine
Output matches §1.5 exactly: `fused_risk_score`, `confidence_state`, `agreement_metric`, `contributing_detectors`. The Decision Engine reads only `fused_risk_score` and `confidence_state` — it does not re-inspect individual detector scores. This keeps the decision thresholds (§4) simple and centralized in one place.

### 2.5 Dashboard → Backend (read contract)
The dashboard, for any given email, needs: the full `emails` row, all `detector_results` rows (for the per-detector breakdown view), the `confidence_scores` row (for the "why" explanation), the `decisions` row, and if applicable the linked `fraud_dna` and `campaigns` rows. This should be served as a single aggregated "email detail" endpoint rather than five separate calls — the dashboard should not orchestrate five queries itself.

---

## 3. Confidence Engine — Exact Specification

This is your core claim. It needs to be precise, not a general description.

### 3.1 Step 1 — Normalize
Every detector's `raw_score` is already normalized to 0.0–1.0 by contract (§2.2). No further normalization needed at this stage.

### 3.2 Step 2 — Weight assignment
Each detector gets a fixed base weight, reflecting how reliable that signal type generally is (this is a design decision your team makes explicitly and documents — don't leave it implicit):
- Sender authentication (SPF/DKIM/DMARC failure): high weight — deterministic, low false-positive signal
- URL model: medium-high weight — strong lexical signal, independent of text model
- Credential detector: medium weight — precise when it fires, but low recall (only fires on explicit patterns)
- XLM-R phishing model: medium-high weight — highest recall, but documented false-positive risk (~5% FPR per general transformer benchmarks) means it shouldn't dominate alone
- Image/QR: medium weight, only counted when `verdict != not_applicable`
- Malware scan: high weight — deterministic signature match, but only applicable to emails with attachments

Weights should sum to 1.0 across all detectors that returned an applicable verdict for a given email (i.e., renormalize per-email based on which detectors actually applied — an email with no attachments and no images redistributes those detectors' weight across the remaining active ones).

### 3.3 Step 3 — Weighted score
`weighted_risk = Σ (detector_weight_i × raw_score_i)` across all applicable detectors, producing a 0.0–1.0 value, then scaled to 0–100 for `fused_risk_score`.

### 3.4 Step 4 — Agreement / disagreement measurement (this is what makes it a *confidence* engine, not just a weighted average)
Compute the variance (or standard deviation) of the individual `raw_score` values across all applicable detectors. Low variance = detectors agree (all high or all low) = CONFIDENT. High variance = detectors disagree (some flag malicious, some flag clean) = UNCERTAIN, regardless of what the weighted average lands on.

**Concrete worked example, to make this unambiguous for implementation:**
- Email A: sender auth fails (0.9), URL model flags (0.85), XLM-R flags (0.8), credential detector n/a → low variance among the three active scores, all high → CONFIDENT, high risk, likely BLOCK.
- Email B: sender auth passes (0.1), URL model flags (0.9), XLM-R doesn't flag (0.15), credential detector n/a → high variance, weighted average lands around 0.4 (medium) → this is exactly the case that should be UNCERTAIN and routed to HUMAN_REVIEW rather than auto-decided at a middling risk score, because the *disagreement itself* is the signal that something needs a second look — a single mid-range detector (URL model) contradicting two others is different from three detectors mildly agreeing on medium risk.

### 3.5 Step 5 — Threshold definitions (document these explicitly, tune during Phase 4 testing)
- `agreement_metric` below a defined variance threshold → CONFIDENT
- `agreement_metric` above that threshold → UNCERTAIN, regardless of `fused_risk_score`
- These thresholds are not fixed in this spec — they must be tuned against your actual labeled test set during Phase 4, and the chosen values (with justification) belong in your paper's methodology section.

### 3.6 Why this design, stated for the paper
This directly answers the documented weakness that single transformer models carry meaningful false-positive rates despite high recall — variance-based disagreement detection is a low-cost, explainable way to catch exactly the cases where a single model's confidence shouldn't be trusted alone, without requiring the model itself to be more complex.

---

## 4. Decision Engine — Threshold Table

| `fused_risk_score` | `confidence_state` | Decision |
|---|---|---|
| 0–20 | CONFIDENT | PASS |
| 21–45 | CONFIDENT | SOFT_PASS |
| 46–70 | CONFIDENT | QUARANTINE |
| 71–100 | CONFIDENT | BLOCK |
| Any range | UNCERTAIN | HUMAN_REVIEW |

**Rule:** UNCERTAIN always overrides the score-based bucket — this is deliberate and is the entire point of having a confidence engine rather than a single fused number. Document your fail-open/fail-closed decision explicitly: if the fusion service itself is down or errors, does an email default to PASS (fail-open, prioritizes availability) or QUARANTINE (fail-closed, prioritizes safety)? Recommend fail-closed (QUARANTINE) for a security product, with a clear note that this creates an operational burden of clearing a backlog if the service has downtime — that trade-off should be a documented decision, not a default nobody chose.

---

## 5. Multilingual (Hindi/Hinglish) Dataset Sourcing Plan

This is your highest-risk dependency. Concrete plan, not "figure it out later":

### 5.1 Labeled phishing/scam data with Hinglish coverage
A multilingual spam corpus covering 23 languages including code-mixed Hinglish, with phishing, crypto-scam, and job-fraud category labels, and released under CC-BY-4.0, is a strong starting point.<cite index="27-1">A multilingual spam dataset called SpamShield packs 149,359 messages across 23 languages, including adversarial patterns like leetspeak, Unicode obfuscation, and code-mixed Hinglish text, with category-level labels covering phishing, crypto scams, and job fraud, published on Hugging Face under a CC-BY-4.0 license.</cite> Use this as your primary source of real labeled Hinglish phishing/scam text.

### 5.2 General Hindi-English code-mixed language coverage (for pretraining/domain adaptation, not phishing-specific labels)
A large-scale real Hindi-English code-mixed corpus of over 52 million sentences scraped from Twitter is available, along with pretrained BERT-family models (HingBERT, HingMBERT, HingRoBERTa) already trained on it.<cite index="24-1">L3Cube-HingCorpus consists of 52.93M sentences and 1.04B tokens of real Hindi-English code-mixed data scraped from Twitter, with accompanying pretrained models HingBERT, HingMBERT, HingRoBERTa, and HingGPT, publicly released on GitHub.</cite> Consider whether to fine-tune `xlm-roberta-base` directly on your labeled phishing data, or to first domain-adapt using HingCorpus/HingRoBERTa before fine-tuning — worth a quick comparison experiment early in Phase 3, since a Hinglish-native base model may outperform generic XLM-R on your specific text style.

### 5.3 Methodological precedent (read this paper before designing your own pipeline)
A closely analogous project built a multilingual smishing (SMS phishing) dataset spanning Bengali, English, Banglish, and code-mixed varieties specifically for a code-mixed phishing detection framework.<cite index="22-1">A multilingual SMS dataset for phishing (smishing) detection covering Bengali, English, Banglish, and Code-Mixed varieties was developed as part of the SmishDetect-LLM research framework, containing 7,005 annotated messages with an 80/20 train-test split.</cite> Read this paper's dataset construction methodology directly — it's the closest published precedent to what you're building for Hindi/Hinglish, and adapting its annotation scheme will save you from designing one from scratch.

### 5.4 A hybrid rule+ML precedent specifically for Hinglish
There's a published framework combining rule-based keyword filtering with ensemble ML specifically for Hinglish spam/scam detection, built explicitly because <cite index="28-1">traditional spam detection systems are designed exclusively for monolingual text and fail to process code-mixed linguistic patterns effectively.</cite> This validates your core thesis directly — cite it in your related-work section, and consider borrowing its keyword-filtering layer as a cheap supplementary signal alongside XLM-R, similar to how your credential detector supplements the phishing model.

### 5.5 Fallback: synthetic augmentation (only if 5.1–5.4 leave you short on volume)
If labeled real Hinglish phishing volume is still insufficient after combining the above sources, generate synthetic code-mixed variants of your labeled English phishing corpus (Nazario) using back-translation or equivalence-constraint-based code-mixing generation — this is an established technique in the code-mixed NLP literature, but label any synthetic data clearly as synthetic in your dataset documentation and don't let it become the majority of your test set (only your training augmentation) — a paper's evaluation should be on real data.

### 5.6 Concrete action item
Before Phase 3 starts: download and inspect the SpamShield dataset's Hinglish subset and the SmishDetect-LLM Bengali paper's methodology, decide your target labeled sample count (recommend minimum 500–1000 Hinglish phishing examples plus a matched legitimate/benign set for a defensible v1 evaluation), and assign one person to own this as their first task, in parallel with Phase 0/1 infrastructure work — not sequentially after.

---

## 6. Service Architecture (Docker Compose Structure — described, not written)

Containers needed, and what each is responsible for:
1. **postgres** — the database from Section 1
2. **redis** — Celery broker + click-time token store (Tier 2)
3. **api** — the FastAPI backend, exposes all REST endpoints, hosts the JWT auth layer
4. **worker** — Celery worker(s), runs the actual detection pipeline asynchronously per email; scale this horizontally under load
5. **gateway** — either the Postfix+milter container, or Rspamd, depending on the team's Phase 2 decision; this is the only container that talks to the outside internet on port 25
6. **clamav** — ClamAV daemon, exposed only internally to the worker container, never to the internet directly
7. **frontend** — the React dashboard, served separately, talks to `api` over HTTP
8. **nginx** — reverse proxy in front of `api` and `frontend`, terminates TLS

**Networking rule:** only `gateway` and `nginx` should have any exposed ports to the outside world. Every other container communicates over the internal Docker network only — this is a basic security posture worth getting right from Phase 1, not retrofitting later.

---

## 7. Evaluation Methodology (decide this before Phase 4, not after)

### 7.1 Test set construction
- Split your combined dataset (English phishing/legit + Hinglish phishing/legit from §5) into train/validation/test with a fixed random seed, documented split ratio (recommend 70/15/15), stratified by language and by malicious/benign label so the test set isn't accidentally English-only or benign-only.
- Keep a held-out "hard negative" set: legitimate emails that superficially resemble phishing (urgent subject lines, financial content, containing links) specifically to test false-positive behavior, not just recall on obvious attacks.

### 7.2 Metrics to report (for both individual detectors and the fused system)
- Precision, Recall, F1, False Positive Rate — for each individual detector alone, and for the fused confidence-engine output, on the same test set
- This side-by-side comparison (single-detector vs. fused) is the single most important table in your paper — it's the direct evidence for your core claim
- Separately report all of the above split by language (English-only subset vs. Hinglish subset) — this is the second most important table, it's the direct evidence for your multilingual claim

### 7.3 Campaign correlation evaluation
- Construct a small test set of known-related phishing variants (same campaign, different domains/wording) from a public dataset or manually curated small set, and report precision/recall of your Fraud DNA clustering against this ground truth — state clearly this is a controlled/simulated evaluation, not a live production measurement, per the honesty note in the original architecture review.

### 7.4 What "good enough for the demo" looks like, concretely
By the Phase 6 checkpoint, you should be able to show: a table of per-detector vs. fused metrics, a table of English vs. Hinglish metrics, at least 3 concrete example emails walked through end-to-end in the dashboard (one clean, one confidently malicious, one that was UNCERTAIN and correctly routed to human review), and the campaign-clustering demo from Phase 5. That combination is what makes the prototype defensible under questioning, not a feature count.

---

## 8. Sources Consulted (this document)
- SpamShield multilingual spam dataset (149K messages, 23 languages) — squaredtech.co
- L3Cube-HingCorpus and HingBERT — arXiv 2204.08398
- SmishDetect-LLM Bengali/Banglish/Code-Mixed smishing dataset — Hugging Face (shariul-islam)
- Hybrid Context-Aware Hinglish Spam and Scam Detection — International Journal of Science, Engineering and Technology
