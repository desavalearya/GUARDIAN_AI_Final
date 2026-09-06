from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.models import Campaign, ComplaintCase, CustodyEvent, Email, EvidenceVault
from backend.privacy.vault import decrypt_raw, encrypt_raw


def _year() -> int:
    return datetime.now(timezone.utc).year


def next_case_ref(db: Session, district: str = "MH") -> str:
    code = "".join(ch for ch in (district or "MH").upper() if ch.isalpha())[:4] or "MH"
    n = db.query(ComplaintCase).count() + 1
    return f"PHISH-{code}-{_year()}-{n:05d}"


def campaign_keys(email: Email) -> list[str]:
    keys: list[str] = []
    if email.sender_address and "@" in email.sender_address:
        keys.append("domain:" + email.sender_address.split("@")[-1].lower())
    for url in email.urls or []:
        if url.domain:
            keys.append("domain:" + url.domain.lower())
    origin = next((d for d in email.detector_results if d.detector_name == "origin_infra"), None)
    ip = (origin.evidence or {}).get("earliest_public_ip") if origin else None
    if ip:
        keys.append("ip:" + str(ip))
    for token in (email.hmac_tokens or {}).values():
        if token:
            keys.append("hmac:" + str(token)[:32])
    return sorted(set(keys))


def attach_campaign(db: Session, email: Email) -> Campaign | None:
    keys = campaign_keys(email)
    if not keys:
        return None
    found = None
    for camp in db.query(Campaign).all():
        existing = set((camp.keys or {}).get("keys") or [])
        if existing & set(keys):
            found = camp
            merged = sorted(existing | set(keys))
            camp.keys = {"keys": merged}
            break
    if found is None:
        found = Campaign(name=keys[0], keys={"keys": keys})
        db.add(found)
        db.flush()
    email.campaign_id = found.id
    return found


def ensure_case(
    db: Session,
    email: Email,
    *,
    victim_mobile: str = "[MOBILE]",
    amount_lost: str = "",
    bank: str = "",
    incident_date: str = "",
    district: str = "MH",
) -> ComplaintCase:
    if email.case:
        return email.case
    case = ComplaintCase(
        case_ref=next_case_ref(db, district),
        email_id=email.id,
        victim_mobile=victim_mobile or "[MOBILE]",
        amount_lost=amount_lost,
        bank=bank,
        incident_date=incident_date,
        district=district,
    )
    db.add(case)
    db.flush()
    return case


def store_vault(db: Session, email: Email, raw: bytes) -> None:
    if email.vault is None:
        db.add(EvidenceVault(email_id=email.id, ciphertext=encrypt_raw(raw), preserved=False))
        db.flush()


def add_custody(
    db: Session,
    email_id: uuid.UUID,
    action: str,
    *,
    actor_id: uuid.UUID | None = None,
    role: str = "",
    detail: dict | None = None,
) -> None:
    db.add(
        CustodyEvent(
            email_id=email_id,
            actor_id=actor_id,
            role=role,
            action=action,
            detail=detail or {},
        )
    )


def fir_pack(email: Email) -> dict:
    origin = next((d for d in email.detector_results if d.detector_name == "origin_infra"), None)
    geo = (origin.evidence or {}).get("geo") if origin else {}
    impersonation = next((d for d in email.detector_results if d.detector_name == "impersonation"), None)
    dec = email.decision.decision if email.decision else ""
    notes = []
    if impersonation and impersonation.verdict != "not_applicable":
        notes.append("Impersonation / lookalike signals present — consider IT Act s.66D language (not legal advice).")
    if email.secret_flags.get("account_last4_mentioned") or email.secret_flags.get("otp_like_pattern"):
        notes.append("Bank-lure / OTP-like patterns were tokenised; digits are not stored.")
    if origin and origin.evidence.get("earliest_public_ip"):
        notes.append(
            f"Probable originating infrastructure {origin.evidence.get('earliest_public_ip')} "
            f"AS{origin.evidence.get('asn')} {origin.evidence.get('aso')} "
            f"({(geo or {}).get('city')}, {(geo or {}).get('country')}). Not an attacker residence."
        )
    notice = {
        "to": origin.evidence.get("aso") if origin else "intermediary",
        "ip": origin.evidence.get("earliest_public_ip") if origin else None,
        "asn": origin.evidence.get("asn") if origin else None,
        "when_ist": email.received_at.isoformat() if email.received_at else "",
        "evidence_hash": email.evidence_sha256,
        "request": "Preserve logs for this hop and advise subscriber details per lawful process.",
    }
    checklist_65b = [
        "Hash of original exhibit recorded (SHA-256 evidence ID)",
        "Custody log: ingested → analyzed → viewed/exported/unlocked",
        "Export is masked; raw unlock is IO-only and logged",
        "Geo/ASN is infrastructure class, not a GPS track",
    ]
    return {
        "decision": dec,
        "evidence_id": email.evidence_sha256,
        "it_act_notes": notes,
        "isp_notice_draft": notice,
        "checklist_65b": checklist_65b,
        "disclaimer": "Draft helper for investigators — not legal advice.",
    }


def masked_report(email: Email) -> dict:
    origin = next((d for d in email.detector_results if d.detector_name == "origin_infra"), None)
    return {
        "evidence_id": email.evidence_sha256,
        "from": email.sender_address,
        "subject": email.subject,
        "body_redacted": email.body_plain,
        "secret_flags": email.secret_flags,
        "hmac_tokens_present": sorted((email.hmac_tokens or {}).keys()),
        "decision": email.decision.decision if email.decision else None,
        "risk": email.confidence.fused_risk_score if email.confidence else None,
        "confidence": email.confidence.confidence_state if email.confidence else None,
        "variance": email.confidence.agreement_metric if email.confidence else None,
        "detectors": [
            {
                "name": d.detector_name,
                "verdict": d.verdict,
                "score": d.raw_score,
                "explanation": d.explanation,
            }
            for d in email.detector_results
        ],
        "origin": (origin.evidence if origin else {}),
        "campaign_id": str(email.campaign_id) if email.campaign_id else None,
        "retention_days": email.retention_days,
        "case_ref": email.case.case_ref if email.case else None,
        "fir": fir_pack(email),
        "custody": [
            {"action": c.action, "role": c.role, "at": c.created_at.isoformat()}
            for c in email.custody_events
        ],
    }


def unlock_raw(db: Session, email: Email) -> str:
    if email.vault is None or not email.vault.preserved:
        raise ValueError("Preserve for FIR first")
    return decrypt_raw(email.vault.ciphertext).decode("utf-8", errors="replace")
