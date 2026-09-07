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
    year = _year()
    # Unique even under concurrent ingest: sequence hint + random suffix.
    for _ in range(8):
        n = db.query(ComplaintCase).count() + 1
        ref = f"PHISH-{code}-{year}-{n:05d}-{uuid.uuid4().hex[:4].upper()}"
        exists = db.query(ComplaintCase.id).filter(ComplaintCase.case_ref == ref).first()
        if exists is None:
            return ref
    return f"PHISH-{code}-{year}-{uuid.uuid4().hex[:12].upper()}"


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


def _pct(score: float | None) -> str:
    if score is None:
        return "n/a"
    return f"{min(99, max(0, int(round(float(score) * 100))))}%"


def forensic_assessment_text(email: Email) -> str:
    """Written cybercell forensic assessment — infrastructure, not attacker GPS."""
    from backend.privacy.redact import mask_local_part

    by = {d.detector_name: d for d in email.detector_results}
    auth = by.get("sender_auth")
    origin = by.get("origin_infra")
    url = by.get("url_model")
    phish = by.get("xlm_r_phishing")
    impersonation = by.get("impersonation")
    conf = email.confidence
    dec = email.decision.decision if email.decision else "UNKNOWN"
    risk = conf.fused_risk_score if conf else None
    variance = conf.agreement_metric if conf else None
    state = conf.confidence_state if conf else "UNKNOWN"

    auth_ev = (auth.evidence if auth else {}) or {}
    origin_ev = (origin.evidence if origin else {}) or {}
    geo = origin_ev.get("geo") or {}
    loc = ", ".join(p for p in (geo.get("city"), geo.get("region"), geo.get("country")) if p) or "unknown"

    classification = "BENIGN"
    if dec in {"HARD_BLOCK", "BLOCK"}:
        classification = "PHISHING / MALICIOUS"
    elif dec in {"QUARANTINE", "HUMAN_REVIEW"}:
        classification = "SUSPICIOUS — NEEDS REVIEW"
    elif dec == "SOFT_PASS":
        classification = "LOW RISK"

    hops = []
    for i, line in enumerate((origin_ev.get("hops") or [])[:6], 1):
        hops.append(f"  Hop {i}: {str(line)[:140]}")

    campaign = ""
    if email.campaign_id:
        campaign = (
            f"Campaign id: {email.campaign_id}\n"
            f"Related infrastructure / keys may link other complaints in SOC → Map / campaigns."
        )
    else:
        campaign = "No campaign cluster linked yet."

    next_steps = [
        "Preserve for FIR if an investigation case is opened (encrypted vault).",
        "Use ISP / intermediary notice draft for the listed ASN/IP (lawful process).",
        "Do not treat GeoIP as the human attacker's residence.",
        "Compare campaign graph for shared domains / IPs / HMAC tokens.",
    ]

    lines = [
        "╔══════════════════════════════════════════════════════════╗",
        "║           EMAIL FORENSIC ASSESSMENT (PhishProof)         ║",
        "╠══════════════════════════════════════════════════════════╣",
        f"║ Case: {(email.case.case_ref if email.case else '—'):<48}║",
        f"║ Evidence ID: {(email.evidence_sha256 or '')[:44]:<44}║",
        f"║ Classification: {classification:<41}║",
        f"║ Decision: {dec:<47}║",
        f"║ Fused risk: {str(risk) if risk is not None else 'n/a':<45}║",
        f"║ Evidence consistency: {state} (variance={variance})".ljust(59) + "║",
        "╠══════════════════════════════════════════════════════════╣",
        "║ 1. EXTRACTED EVIDENCE                                    ║",
        f"║ From (masked): {mask_local_part(email.sender_address):<40}║",
        f"║ Display: {(email.sender_display_name or '—')[:48]:<48}║",
        f"║ Subject: {(email.subject or '')[:48]:<48}║",
        f"║ URLs stored: {len(email.urls or []):<44}║",
        f"║ Attachments (hash-only): {len(email.attachments or []):<33}║",
        "╠══════════════════════════════════════════════════════════╣",
        "║ 2. SENDER AUTHENTICATION                                 ║",
        f"║ SPF:   {str(auth_ev.get('spf')):<50}║",
        f"║ DKIM:  {str(auth_ev.get('dkim')):<50}║",
        f"║ DMARC: {str(auth_ev.get('dmarc')):<50}║",
        f"║ Auth identity used: {str(auth_ev.get('spf_identity') or '')[:37]:<37}║",
        f"║ Alignment: {str((auth_ev.get('alignment') or {}))[:46]:<46}║",
        f"║ Auth confidence: {_pct(1.0 - (auth.raw_score if auth else 0.5)):<42}║",
        "╠══════════════════════════════════════════════════════════╣",
        "║ 3. EARLIEST RELIABLE INFRASTRUCTURE                       ║",
        f"║ IP: {str(origin_ev.get('earliest_public_ip') or 'NOT ESTABLISHED'):<53}║",
        f"║ ASN: AS{str(origin_ev.get('asn') or '—')} {(origin_ev.get('aso') or '')[:40]:<40}║",
        f"║ Type: {str(origin_ev.get('infra_class') or 'unknown'):<51}║",
        f"║ GeoIP (infrastructure): {loc[:33]:<33}║",
        f"║ Path reliable: {str(origin_ev.get('reliable')):<42}║",
        f"║ Note: {str(origin_ev.get('relay_note') or '')[:51]:<51}║",
        "╠══════════════════════════════════════════════════════════╣",
        "║ 4. OBSERVABLE RELAY PATH (newest → older)                 ║",
    ]
    if hops:
        for h in hops:
            lines.append(f"║ {h[:56]:<56}║")
    else:
        lines.append("║   (no Received hops in this exhibit)                     ║")

    lines.extend(
        [
            "╠══════════════════════════════════════════════════════════╣",
            "║ 5. CONTENT / URL / THREAT SIGNALS                         ║",
            f"║ Text model: {(phish.verdict if phish else 'n/a')} score={phish.raw_score if phish else 'n/a'}".ljust(59) + "║",
            f"║ URL model: {(url.verdict if url else 'n/a')} score={url.raw_score if url else 'n/a'}".ljust(59) + "║",
            f"║ Impersonation: {(impersonation.verdict if impersonation else 'n/a')}".ljust(59) + "║",
            "╠══════════════════════════════════════════════════════════╣",
            "║ 6. CORRELATION                                            ║",
            f"║ {campaign[:56]:<56}║",
            "╠══════════════════════════════════════════════════════════╣",
            "║ 7. CONFIDENCE SUMMARY                                     ║",
            f"║ Email maliciousness (fused): {str(risk) + '%' if risk is not None else 'n/a':<28}║",
            f"║ Sender spoof / auth risk: {_pct(auth.raw_score if auth else None):<31}║",
            f"║ Infra class confidence: {_pct(0.99 if origin_ev.get('infra_class') else 0):<33}║",
            "║ Physical attacker location: NOT ESTABLISHED               ║",
            "╠══════════════════════════════════════════════════════════╣",
            "║ 8. INVESTIGATOR NEXT STEPS                                ║",
        ]
    )
    for step in next_steps:
        lines.append(f"║ - {step[:54]:<54}║")
    lines.append("╚══════════════════════════════════════════════════════════╝")
    lines.append("")
    lines.append(
        "Disclaimer: GeoIP/ASN describe probable originating *infrastructure* "
        "(provider datacenter / hosting), never a guaranteed human GPS location."
    )
    fir = fir_pack(email)
    if fir.get("isp_notice_draft"):
        lines.append("")
        lines.append("--- ISP / intermediary notice draft ---")
        for k, v in fir["isp_notice_draft"].items():
            lines.append(f"{k}: {v}")
    if fir.get("it_act_notes"):
        lines.append("")
        lines.append("--- IT Act helper notes (not legal advice) ---")
        for n in fir["it_act_notes"]:
            lines.append(f"- {n}")
    if fir.get("checklist_65b"):
        lines.append("")
        lines.append("--- 65B checklist ---")
        for n in fir["checklist_65b"]:
            lines.append(f"- {n}")
    return "\n".join(lines)


def masked_report(email: Email) -> dict:
    from backend.privacy.redact import mask_local_part

    origin = next((d for d in email.detector_results if d.detector_name == "origin_infra"), None)
    text = forensic_assessment_text(email)
    return {
        "evidence_id": email.evidence_sha256,
        "from": mask_local_part(email.sender_address),
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
        "report_text": text,
    }


def unlock_raw(db: Session, email: Email) -> str:
    if email.vault is None or not email.vault.preserved:
        raise ValueError("Preserve for FIR first")
    return decrypt_raw(email.vault.ciphertext).decode("utf-8", errors="replace")
