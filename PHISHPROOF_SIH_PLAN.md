# PhishProof — How We Build From Here

**Product spec (source of truth):** [`PHISHPROOF_COMPLETE_FINAL.md`](./PHISHPROOF_COMPLETE_FINAL.md)  
Copied from `E:\SIH\PHISHPROOF_COMPLETE_FINAL.md`. Older Guardian execution plans in this repo are historical only.

**URL models:** live path uses **`models/url/v1`** (`url-xgb-v1`, ~89.7% test accuracy, ROC-AUC 94.69%). Root `models/url/*` (except `v1/`) stays parked. Heuristics remain as fallback if the model fails to load.

---

## Status (6 Sep 2026)

- Live path uses **XLM-R + Office + PDF v3** (falls back to heuristics if a model fails).
- URL = **url-xgb-v1** (`models/url/v1`) with heuristic fallback. Card: **89.73% accuracy**, ROC-AUC **94.69%**, FPR **~1%** at cutoff 0.9062; recall at that strict cutoff ~60% (production soft thresholds 0.35 / 0.70).
- SOC can **Upload .eml** on http://localhost:5174 (same engine as SMTP).
- Demo files: `fixtures/demo_eml/case1_clean.eml` → `PASS`; `case2_bank_lookalike.eml` → `HARD_BLOCK` (XLM-R + URL + impersonation).
- QR decode runs if pyzbar/OpenCV is installed; otherwise images are noted and HTML/QR URLs still go through URL heuristics when decoded later.
- Phase 2 origin is live: earliest public Received IP → GeoLite2 City+ASN → cloud/VPN/TOR class → cached WHOIS. Language is **probable originating infrastructure**, not attacker GPS.
- Case 2 demo now includes a DigitalOcean hop (`167.99.140.10` → Frankfurt, AS14061) plus Reply-To mismatch.
- Phases 3–5 are wired: impersonation, recon-pixel, SVG/ICS, TOAD/device-code/invoice, ATO baseline, campaign merge, privacy tokens, vault, cases, FIR pack, Leaflet map.
- Demo files in `fixtures/demo_eml/`: clean PASS; bank lookalike HARD_BLOCK with `[ACCT_LAST4]`/`[OTP]`; QR BLOCK; TOAD QUARANTINE; trusted-mailbox ATO HUMAN_REVIEW.
- Upload those five files on SOC (`:5174`) to persist cases. Recreating the API container still drops in-container pip until the image is rebuilt.

## Already in place (reuse, do not rebuild)

- Postfix + milter, FastAPI, Postgres, Redis, Docker Compose
- Mail Client `:5173`, SOC `:5174`, API `:8000`
- Variance fusion + decision ladder
- SPF / DKIM / DMARC, SHA-256 (extend to evidence ID)
- GeoLite2 City + ASN databases on disk (`data/geoip/`)
- Model Lab: XLM-R (`models/email`), Office (`models/doc`), PDF **v3** (`models/PDF_v3`)
- PDF v3: ~89% malicious recall, ~0.7% FPR; IEEE/real docs CLEAN (not a single “accuracy %” on the card)

---

## Build order (this is what happens next)

Work stays in **this repo**. No second app. No `docker compose up --build` unless requirements actually change.

### Phase 1 — Live detection (gateway, not only Lab)

1. Wire **XLM-R + Office + PDF v3** into `backend/detection/engine.py` (live SMTP / `.eml` path).
2. Keep **URL as heuristics** until the new model arrives; then swap the URL detector only.
3. Replace QR/OCR stub: decode → same URL pipeline (heuristics now, new model later).

### Phase 2 — Origin (Fast Path)

4. Parse Received headers → earliest **reliable** relay IP.
5. GeoLite2 City + ASN / ISP class (DBs already present).
6. VPN / TOR / cloud lists (offline files).
7. Cached WHOIS / DNS / MX for demo domains (no live WHOIS in the pitch).

### Phase 3 — Extra signals

8. Impersonation (Levenshtein + homograph).
9. Recon-pixel, SVG/ICS, NLP + TOAD / device-code / invoice drift.
10. ATO baseline (pre-seed 5–10 mails) + campaign graph (pre-seed).

### Phase 4 — Evidence & Privacy Manager (Cyber Cell)

11. Secret detector (OTP, last-4, PAN, Aadhaar, card, IFSC).
12. Analyse full mail in RAM → persist **tokens + scores**, never cleartext secrets.
13. HMAC tokens for campaign match (not SHA-256 of last-4).
14. Encrypted vault + Preserve for FIR + dual-control unlock + custody log.
15. Masked forensic JSON + retention field.

### Phase 5 — SOC / judges

16. Complaint intake → case id, alert banner, Leaflet map + graph.
17. FIR / 65B notes + ISP notice draft.
18. Five demo `.eml` files (clean, bank+tokenised last-4, QR, TOAD, ATO `HUMAN_REVIEW`).

---

## Parked (not SIH)

ClamAV/YARA, trained XGBoost fusion, DLP, SIEM, Nginx/TLS, Celery-only rewrite, Graph/Gmail, live VirusTotal, old URL artifacts, OAuth/AiTM as live features.

---

## Definition of done (judges)

Upload/send mail → Fast Path + Deep Path → variance decision → infra map (not “attacker city”) → alert → case/graph → **masked** report + custody → Case 5 `HUMAN_REVIEW` → Case 2 shows `[ACCT_LAST4]` not digits → Preserve for FIR logs unlock.
