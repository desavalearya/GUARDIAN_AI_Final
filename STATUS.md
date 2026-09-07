# Status (historical)

This file is a leftover from early Guardian scaffolding.

**Current SIH truth:** [`PHISHPROOF_COMPLETE_FINAL.md`](./PHISHPROOF_COMPLETE_FINAL.md) and [`PHISHPROOF_SIH_PLAN.md`](./PHISHPROOF_SIH_PLAN.md).

Live path uses XLM-R + Office + PDF v3 + URL v1 (with heuristic fallback). Privacy Manager redacts OTP/last-4/PAN/AWS/JWT/private keys before persist. Vault and HMAC use **dedicated** secrets (`VAULT_SECRET`, `HMAC_SECRET`), not JWT. Retention is enforced hourly by the Celery worker (`--beat`).

Do not treat older claims in this file (Lab-only models, incomplete privacy) as current.
