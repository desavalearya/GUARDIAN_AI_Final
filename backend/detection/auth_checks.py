from __future__ import annotations

import logging
import re

from backend.detection.relay import header_values, parse_relay_path
from backend.detection.types import DetectorOutput, verdict_from_score as _verdict
from backend.email.parser import ParsedEmail

log = logging.getLogger(__name__)

AUTH_HEADER_NAMES = (
    "authentication-results",
    "arc-authentication-results",
)
AUTH_TOKEN_RE = re.compile(
    r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
DKIM_D_RE = re.compile(r"\bheader\.d=([^\s;]+)", re.IGNORECASE)
SPF_MAILFROM_RE = re.compile(r"\bsmtp\.mailfrom=([^\s;]+)", re.IGNORECASE)


def _org_domain(domain: str) -> str:
    parts = [p for p in (domain or "").lower().strip(".").split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()


def _auth_results_blob(raw_headers: str) -> str:
    """Only Authentication-Results / ARC-Authentication-Results — never whole headers."""
    chunks: list[str] = []
    for name in AUTH_HEADER_NAMES:
        chunks.extend(header_values(raw_headers, name))
    return "\n".join(chunks)


def _parse_auth_results(blob: str) -> dict:
    out: dict = {"spf": None, "dkim": None, "dmarc": None, "spf_mailfrom": "", "dkim_d": ""}
    if not blob:
        return out
    for match in AUTH_TOKEN_RE.finditer(blob):
        key = match.group(1).lower()
        val = match.group(2).lower()
        # Prefer fail over pass if both appear (stricter).
        if out[key] == "fail":
            continue
        if val == "fail" or out[key] is None:
            out[key] = val
    mf = SPF_MAILFROM_RE.search(blob)
    if mf:
        out["spf_mailfrom"] = mf.group(1).strip().lower()
    dd = DKIM_D_RE.search(blob)
    if dd:
        out["dkim_d"] = dd.group(1).strip().lower().rstrip(".")
    return out


def _aligned(from_domain: str, candidate: str) -> bool:
    if not from_domain or not candidate:
        return False
    cand = candidate.split("@")[-1].lower().rstrip(".")
    return _org_domain(from_domain) == _org_domain(cand) or cand.endswith("." + _org_domain(from_domain))


def run_sender_auth(parsed: ParsedEmail) -> DetectorOutput:
    """SPF + DKIM + DMARC with header-source discipline and alignment."""
    evidence: dict = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "sender": parsed.sender_address,
        "display_name": parsed.sender_display_name,
        "alignment": {},
        "auth_header_source": "authentication-results|arc-authentication-results",
    }
    reasons: list[str] = []
    score = 0.1

    display = (parsed.sender_display_name or "").lower()
    sender = (parsed.sender_address or "").lower()
    from_domain = sender.split("@")[-1] if "@" in sender else ""

    OFFICIAL = {
        "paypal": ("paypal.com",),
        "microsoft": ("microsoft.com", "outlook.com", "live.com", "office.com"),
        "google": ("google.com", "gmail.com", "googlemail.com"),
        "amazon": ("amazon.com", "amazon.in"),
        "apple": ("apple.com", "icloud.com"),
        "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbi.com"),
        "hdfc": ("hdfcbank.com", "hdfc.com"),
        "icici": ("icicibank.com", "icici.com"),
        "bank": (),
    }
    for brand, official in OFFICIAL.items():
        if brand in display:
            if official and not any(from_domain == o or from_domain.endswith("." + o) for o in official):
                score = max(score, 0.78)
                reasons.append(f"display-brand-unofficial-domain:{brand}")
            elif not official and brand == "bank" and not any(
                b in from_domain for b in ("sbi", "hdfc", "icici", "axis", "bank")
            ):
                score = max(score, 0.75)
                reasons.append("display-name brand does not match From domain")

    auth_blob = _auth_results_blob(parsed.raw_headers)
    parsed_ar = _parse_auth_results(auth_blob)
    for key in ("spf", "dkim", "dmarc"):
        if parsed_ar.get(key):
            evidence[key] = parsed_ar[key]

    if evidence["spf"] == "fail":
        score = max(score, 0.9)
        reasons.append("SPF fail in Authentication-Results")
    elif evidence["spf"] == "softfail":
        score = max(score, 0.55)
        reasons.append("SPF softfail in Authentication-Results")
    # Auth pass must NOT lower an existing threat score (issue 31).

    if evidence["dkim"] == "fail":
        score = max(score, 0.7)
        reasons.append("DKIM fail in Authentication-Results")

    if evidence["dmarc"] == "fail":
        score = max(score, 0.85)
        reasons.append("DMARC fail in Authentication-Results")
    elif evidence["dmarc"] == "pass":
        # Require alignment with visible From domain.
        aligned = _aligned(from_domain, parsed_ar.get("dkim_d") or "") or _aligned(
            from_domain, parsed_ar.get("spf_mailfrom") or ""
        )
        evidence["alignment"]["dmarc_header_pass"] = True
        evidence["alignment"]["from_aligned"] = aligned
        if not aligned and from_domain:
            evidence["dmarc"] = "pass_unaligned"
            score = max(score, 0.55)
            reasons.append("DMARC header pass but From domain not aligned")

    path = parse_relay_path(parsed.raw_headers)
    relay_ip = path.earliest_public_ip
    evidence["relay_ip"] = relay_ip
    evidence["relay_note"] = path.note

    # Prefer Return-Path identity for live SPF when available.
    return_paths = header_values(parsed.raw_headers, "return-path")
    mailfrom = sender
    if return_paths:
        match = re.search(r"([\w.+-]+@[\w.-]+)", return_paths[0] or "")
        if match:
            mailfrom = match.group(1).lower()
    evidence["spf_identity"] = mailfrom

    if evidence["spf"] is None and mailfrom and "@" in mailfrom:
        if not relay_ip:
            evidence["spf"] = "none"
            reasons.append("no public relay IP; SPF not evaluated")
        else:
            evidence["spf"] = _check_spf(mailfrom, relay_ip)
            if evidence["spf"] == "fail":
                score = max(score, 0.85)
                reasons.append("SPF DNS check failed for Return-Path/From identity")

    if evidence["dkim"] is None and parsed.raw_message:
        evidence["dkim"] = _check_dkim(parsed.raw_message)
        if evidence["dkim"] == "fail":
            score = max(score, 0.65)
            reasons.append("DKIM signature invalid")
        elif evidence["dkim"] == "none":
            reasons.append("no DKIM signature")

    if evidence["dmarc"] is None and from_domain:
        if not relay_ip:
            evidence["dmarc"] = "none"
        else:
            evidence["dmarc"] = _check_dmarc(
                from_domain,
                evidence.get("spf"),
                evidence.get("dkim"),
                parsed_ar.get("dkim_d") or "",
                parsed_ar.get("spf_mailfrom") or mailfrom,
            )
            if evidence["dmarc"] == "fail":
                score = max(score, 0.8)
                reasons.append("DMARC not aligned with From domain")
            elif evidence["dmarc"] == "pass":
                evidence["alignment"]["from_aligned"] = True

    if not sender or "@" not in sender:
        score = max(score, 0.9)
        reasons.append("missing From address")

    missing_only = {
        "no public relay IP; SPF not evaluated",
        "no DKIM signature",
    }
    # Display-brand / alignment reasons must still vote even if SPF/DKIM are "none".
    if score < 0.4 and set(reasons) <= missing_only:
        return DetectorOutput(
            detector_name="sender_auth",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="; ".join(reasons) if reasons else "No authentication signal to vote.",
            evidence=evidence,
            model_version="auth-spf-dkim-dmarc-v2",
        )

    return DetectorOutput(
        detector_name="sender_auth",
        raw_score=round(min(score, 0.99), 3),
        verdict=_verdict(score),
        explanation="; ".join(reasons) if reasons else "SPF/DKIM/DMARC checks completed.",
        evidence=evidence,
        model_version="auth-spf-dkim-dmarc-v2",
    )


def _check_spf(identity: str, ip: str) -> str:
    try:
        import spf

        result = spf.check2(i=ip, s=identity, h="unknown")
        status = (result[0] or "").lower()
        if status in {"pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"}:
            return "pass" if status == "pass" else ("fail" if status in {"fail", "permerror"} else status)
        return status or "none"
    except Exception as exc:
        log.debug("spf check skipped: %s", exc)
        return "none"


def _check_dkim(raw_message: str) -> str:
    try:
        import dkim

        msg = raw_message.encode("utf-8", errors="replace")
        if b"DKIM-Signature:" not in msg and b"dkim-signature:" not in msg.lower():
            return "none"
        ok = dkim.verify(msg)
        return "pass" if ok else "fail"
    except Exception as exc:
        log.debug("dkim check skipped: %s", exc)
        return "none"


def _check_dmarc(
    from_domain: str,
    spf: str | None,
    dkim: str | None,
    dkim_d: str,
    spf_mailfrom: str,
) -> str:
    """DMARC-like: authenticated identity must align with From org domain."""
    try:
        import checkdmarc

        data = checkdmarc.check_domains([from_domain])
        records = data.get("domains", data) if isinstance(data, dict) else data
        has_dmarc = False
        if isinstance(records, list) and records:
            has_dmarc = bool((records[0].get("dmarc") or {}).get("record"))
        elif isinstance(records, dict):
            has_dmarc = bool((records.get("dmarc") or {}).get("record"))
        if not has_dmarc:
            # Still apply alignment logic when either auth method passed.
            pass
    except Exception as exc:
        log.debug("dmarc DNS skipped: %s", exc)

    spf_ok = spf == "pass" and _aligned(from_domain, spf_mailfrom or "")
    dkim_ok = dkim == "pass" and (_aligned(from_domain, dkim_d) if dkim_d else True)
    if spf_ok or dkim_ok:
        return "pass"
    if spf == "fail" and dkim in {None, "fail", "none"}:
        return "fail"
    if (spf == "pass" or dkim == "pass") and not (spf_ok or dkim_ok):
        return "fail"
    return "none"
