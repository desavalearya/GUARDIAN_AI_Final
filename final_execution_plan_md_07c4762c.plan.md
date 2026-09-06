---
name: Final Execution Plan MD
overview: Keep both existing Guardian MD files untouched. Create one ultra-detailed, senior-dev spoonfeeding markdown (Guardian_AI_Final_Execution_Plan.md) covering installs, dependencies, model compatibility, gap Adds/Upgrades, verdict, and phase-by-phase build steps with checkpoints—documentation only, no code.
todos:
  - id: write-final-md
    content: "Write Guardian_AI_Final_Execution_Plan.md: verdict, how-to-read, pre-flight installs, full deps + model compatibility matrix, architecture, Add/Upgrade/Park sections, then Phases 0–12 with spoonfeeding steps, verify commands, pitfalls, Tier-1 done criteria, and cross-refs to Guardian BP/TS"
    status: pending
isProject: false
---

# Ultra-Detailed Final Execution Plan Markdown

## Decision (locked)

- **Do not edit** [Guardian_AI_Build_Plan (1).md](Guardian_AI_Build_Plan%20(1).md) or [Guardian_AI_Technical_Specification.md](Guardian_AI_Technical_Specification.md).
- **Create exactly one new file:** [Guardian_AI_Final_Execution_Plan.md](Guardian_AI_Final_Execution_Plan.md) at `D:\SMTP_NEW_PROJECT\`.
- **No application code, Dockerfiles, notebooks, or scaffolding** — documentation only.
- Tone: senior engineer spoonfeeding a team from zero — every phase says *what*, *why*, *install*, *build order*, *how to verify*, *common mistakes*.

## Deliverable shape (single MD outline)

### A. How to use this document
- Reading order: this file (build order of record) → Technical Spec (schemas/contracts/confidence math) → Build Plan (folder layout / team roles / stretch ideas).
- Conflict rule: **this file + Technical Spec §3 override Build Plan Phase 5** wherever Build Plan says XGBoost also outputs CONFIDENT/UNCERTAIN.

### B. Final verdict on the idea
- Thesis is sound and buildable.
- Tier 1 scope (what to build first) vs Tier 2 (park until Tier 1 demos green).
- Main failure mode: trying to build Graph/BEC/remediation/click-rewrite before fusion + confidence work.

### C. Pre-flight — install BEFORE any project code
Complete checklist with purpose for each item:

**Host / OS tools**
- Git, Docker Desktop (or Engine + Compose), Python 3.11+, Node.js 20+, npm, VS Code (or equivalent)

**System packages**
- `tesseract-ocr`, `libzbar0` / zbar, ClamAV daemon (or Compose image), YARA

**Accounts / keys to register early**
- VirusTotal (Tier 2), Azure app + Google Cloud (Tier 2 only), test domain for SPF/DKIM/DMARC

**Datasets to download before Phase 3 training**
- Nazario, SpamAssassin, PhishTank/URLhaus, Tranco/legit URLs, SpamShield Hinglish subset, Enron (Tier 2 BEC), EICAR only for malware smoke tests

**Machine expectations**
- RAM/GPU notes for XLM-R fine-tune vs CPU inference for demo

### D. Dependency lock — libraries and versions
- Backend: FastAPI, Uvicorn/Gunicorn, Pydantic, SQLAlchemy, Alembic, Celery, Redis client, PyJWT/passlib, pyspf/dkimpy/checkdmarc/dnspython, pymilter
- ML: torch, transformers, xlm-roberta-base, xgboost, scikit-learn, numpy, pandas, sentence-transformers (Fraud DNA), ssdeep/TLSH
- Media: pytesseract, opencv-python, pyzbar
- Malware: clamd / yara-python, pefile
- Frontend: React, TypeScript, Vite (or CRA as noted), Material UI, Recharts
- Deploy: Nginx, TLS 1.3, Docker Compose
- Provide a **compatibility matrix** answering: are models + pipeline compatible?

| Component | Role | Independent for confidence? | Feeds XGBoost risk? | Conflicts with? |
|---|---|---|---|---|
| XLM-R | semantic phishing | Yes | Yes (as feature) | Do not also use as “agreement peer” vs XGBoost |
| XGBoost | risk fusion only | **No** | N/A (is the fusion) | Must not vote on CONFIDENT/UNCERTAIN |
| TF-IDF + LogReg URL | URL malice | Yes | Yes | None if QR/OCR URLs reuse same model |
| Regex + Entropy | secrets | Yes | Yes | OTP allowlist rules separate inbound vs outbound |
| SPF/DKIM/DMARC | auth | Yes | Yes | Deterministic |
| ClamAV/YARA | malware | Yes when applicable | Yes | High weight when fires |
| Image/OCR/QR | extractors | Indirect (via URL/text) | Via downstream scores | Not a second URL model |
| Isolation Forest BEC | Tier 2 | Yes when built | Yes | Park until Tier 1 |
| Fraud DNA / ssdeep | post-decision intel | No (not confidence) | Optional boost later | After QUARANTINE/BLOCK |

Also call out **version pitfalls**: Python 3.11 vs torch wheels; milter needs Linux/container (Windows host → Postfix in Docker); Tesseract system binary required; Celery + Redis broker must match.

### E. What we are building (product definition)
- One-sentence thesis + Tier 1 feature list (previous 30 + Guardian malware/Fraud DNA/Hinglish-eval + Adds).
- Explicit **not in Tier 1** list.

### F. Architecture of record
- Mermaid end-to-end flow (ingest → auth/dedup → parallel detectors → confidence + risk + booster → decision → enforce/quarantine/review → SIEM/campaigns).
- Decision table with PASS / SOFT_PASS / QUARANTINE / BLOCK / HARD_BLOCK + UNCERTAIN → HUMAN_REVIEW.
- Fail-closed = QUARANTINE.

### G. Gap closure written in full (Adds + Upgrades + Park)
Same content as prior plan (dedup, booster, HARD_BLOCK, DLP, SIEM HMAC, alerting, audit, rate limit, RBAC, OTP allowlist, explainability upgrade, schema deltas) — fully specified so coding later does not require guessing.

### H. Folder structure and team roles
- Point to Build Plan §6–§7; paste the tree once so the spoonfeeding file stands alone for daily use.

### I. Phases 0–12 — spoonfeeding format (every phase)

For **each** phase, the MD will include these fixed subsections:

1. **Goal** — one sentence  
2. **What you are building** — concrete modules/services  
3. **Prerequisites** — which prior phase checkpoint must be green  
4. **Install / enable for this phase** — only new deps/packages for this phase  
5. **Implementation steps** — numbered, order matters (create X, then Y, then wire Z)  
6. **Key interfaces** — which TS contracts apply (detector_results shape, etc.)  
7. **How to verify** — exact checkpoint (API call, sample email, expected decision)  
8. **Common pitfalls** — 2–4 mistakes  
9. **Owner hint** — from Build Plan roles  

**Phase list (locked):**

| Phase | Focus |
|---|---|
| 0 | Team/repo, `.env.example`, board, branch protection |
| 1 | Compose: Postgres, Redis, FastAPI health, JWT skeleton, Alembic, Celery hello |
| 2 | Postfix+milter, shared parser, SHA-256 dedup, store email rows |
| 3 | Detectors isolated: auth → creds+allowlist → URL train/serve → image/QR → XLM-R → malware |
| 4 | Confidence (TS §3) + XGBoost risk + Risk Booster + Decision (+ HARD_BLOCK, fail-closed) |
| 5 | Inbound enforce + outbound scan + DLP policy engine |
| 6 | Quarantine store + split human-review queues + explainability API |
| 7 | React SOC dashboard (threat list, detail, quarantine, campaigns placeholder) |
| 8 | Fraud DNA + campaign clustering |
| 9 | SIEM HMAC, alerting webhooks, audit_logs, RBAC, rate limiting |
| 10 | Nginx + TLS 1.3 + Compose packaging hardening + secrets discipline |
| 11 | E2E matrix (spoof, phish, creds, URL, QR, legit, conflict) + load test + go-live review |
| 12 | Tier 2 only: Graph/Gmail, WHOIS/VT, URL rewrite, BEC, auto-remediation, honeypot/red team, stretch |

Phase 3 will include a **mini training playbook**: offline notebook → evaluate → export artifact → load in API; Hinglish dataset actions from TS §5 without re-copying the whole paper list.

### J. Done for v1 + demo script
- Checklist of Tier 1 phases green.
- Three live walkthroughs: clean PASS, confident BLOCK/HARD_BLOCK, UNCERTAIN conflict → human review.
- Metrics tables required (from TS §7): per-detector vs fused; English vs Hinglish.

### K. Cross-reference appendix
- Map: Final Plan section → Build Plan section → Technical Spec section.

## Out of scope for this task

- Editing existing Guardian MDs  
- Writing any application code  
- Creating any file other than `Guardian_AI_Final_Execution_Plan.md`

## Execution note (after you approve this plan)

Write the full spoonfeeding markdown in one pass; keep it long and concrete; no partial stubs like “TBD” or “optional — decide later” for Tier 1 decisions already locked above.
