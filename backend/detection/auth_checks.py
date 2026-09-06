from __future__ import annotations

import logging

from backend.detection.types import DetectorOutput, verdict_from_score as _verdict
from backend.email.parser import ParsedEmail

log = logging.getLogger(__name__)


def run_sender_auth(parsed: ParsedEmail) -> DetectorOutput:
    """Real SPF + DKIM + DMARC checks with heuristic fallback."""
    evidence: dict = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "sender": parsed.sender_address,
        "display_name": parsed.sender_display_name,
    }
    reasons: list[str] = []
    score = 0.1

    # Display-name brand mismatch (BEC-ish signal)
    display = (parsed.sender_display_name or "").lower()
    sender = (parsed.sender_address or "").lower()
    if any(brand in display for brand in ("paypal", "microsoft", "google", "amazon", "bank", "apple")):
        domain = sender.split("@")[-1] if "@" in sender else ""
        if domain and not any(brand in domain for brand in ("paypal", "microsoft", "google", "amazon", "bank", "apple")):
            score = max(score, 0.75)
            reasons.append("display-name brand does not match From domain")

    # Prefer Authentication-Results / ARC headers if present (OpenDMARC/OpenDKIM)
    headers_l = parsed.raw_headers.lower()
    if "spf=fail" in headers_l:
        score = max(score, 0.9)
        evidence["spf"] = "fail"
        reasons.append("SPF fail in Authentication-Results")
    elif "spf=pass" in headers_l:
        evidence["spf"] = "pass"
        score = min(score, 0.15)
    elif "spf=softfail" in headers_l:
        evidence["spf"] = "softfail"
        score = max(score, 0.55)
        reasons.append("SPF softfail")

    if "dkim=fail" in headers_l:
        evidence["dkim"] = "fail"
        score = max(score, 0.7)
        reasons.append("DKIM fail")
    elif "dkim=pass" in headers_l:
        evidence["dkim"] = "pass"

    if "dmarc=fail" in headers_l:
        evidence["dmarc"] = "fail"
        score = max(score, 0.85)
        reasons.append("DMARC fail")
    elif "dmarc=pass" in headers_l:
        evidence["dmarc"] = "pass"

    # Live DNS only when we have a non-loopback relay. Uploaded .eml files
    # usually have no Received hop — scoring those as SPF fail causes false blocks.
    from backend.detection.relay import parse_relay_path

    relay_ip = parse_relay_path(parsed.raw_headers).earliest_public_ip
    evidence["relay_ip"] = relay_ip

    if evidence["spf"] is None and sender and "@" in sender:
        if not relay_ip:
            evidence["spf"] = "none"
            reasons.append("no public relay IP; SPF not evaluated")
        else:
            evidence["spf"] = _check_spf(parsed, relay_ip)
            if evidence["spf"] == "fail":
                score = max(score, 0.85)
                reasons.append("SPF DNS check failed")
            elif evidence["spf"] == "pass":
                score = min(score, max(score, 0.12))

    if evidence["dkim"] is None and parsed.raw_message:
        evidence["dkim"] = _check_dkim(parsed.raw_message)
        if evidence["dkim"] == "fail":
            score = max(score, 0.65)
            reasons.append("DKIM signature invalid")
        elif evidence["dkim"] == "none":
            reasons.append("no DKIM signature")
        elif evidence["dkim"] == "pass":
            pass

    if evidence["dmarc"] is None and sender and "@" in sender:
        if not relay_ip:
            evidence["dmarc"] = "none"
        else:
            evidence["dmarc"] = _check_dmarc(sender.split("@")[-1], evidence.get("spf"), evidence.get("dkim"))
            if evidence["dmarc"] == "fail":
                score = max(score, 0.8)
                reasons.append("DMARC policy not aligned")
            elif evidence["dmarc"] == "pass":
                score = min(score, 0.2)

    if not sender or "@" not in sender:
        score = max(score, 0.9)
        reasons.append("missing From address")

    missing_only = {
        "no public relay IP; SPF not evaluated",
        "no DKIM signature",
    }
    auth_passed = any(evidence.get(k) == "pass" for k in ("spf", "dkim", "dmarc"))
    if score < 0.4 and set(reasons) <= missing_only and not auth_passed:
        return DetectorOutput(
            detector_name="sender_auth",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="; ".join(reasons) if reasons else "No authentication signal to vote.",
            evidence=evidence,
            model_version="auth-spf-dkim-dmarc-v1",
        )

    return DetectorOutput(
        detector_name="sender_auth",
        raw_score=round(min(score, 0.99), 3),
        verdict=_verdict(score),
        explanation="; ".join(reasons) if reasons else "SPF/DKIM/DMARC checks completed.",
        evidence=evidence,
        model_version="auth-spf-dkim-dmarc-v1",
    )


def _check_spf(parsed: ParsedEmail, ip: str) -> str:
    try:
        import spf

        helo = "unknown"
        result = spf.check2(i=ip, s=parsed.sender_address, h=helo)
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


def _check_dmarc(domain: str, spf: str | None, dkim: str | None) -> str:
    try:
        import checkdmarc

        data = checkdmarc.check_domains([domain])
        # If DMARC record exists and neither SPF nor DKIM passed, fail-ish
        records = data.get("domains", data) if isinstance(data, dict) else data
        has_dmarc = False
        if isinstance(records, list) and records:
            dmarc = records[0].get("dmarc", {})
            has_dmarc = bool(dmarc.get("record"))
        elif isinstance(records, dict):
            has_dmarc = bool(records.get("dmarc", {}).get("record"))
        if not has_dmarc:
            return "none"
        if spf == "pass" or dkim == "pass":
            return "pass"
        if spf == "fail" and dkim in {None, "fail", "none"}:
            return "fail"
        return "none"
    except Exception as exc:
        log.debug("dmarc check skipped: %s", exc)
        if spf == "pass" or dkim == "pass":
            return "pass"
        return "none"
