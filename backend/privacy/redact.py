"""Scan in RAM, persist tokens/flags — never OTP / last-4 / PAN digits."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field

from backend.config import settings

OTP_RE = re.compile(r"\b(\d{6})\b")
LAST4_RE = re.compile(r"\b(?:a/?c|account|ending|xxxx|xx)\D{0,12}(\d{4})\b", re.IGNORECASE)
BARE_LAST4_RE = re.compile(r"\bending\s+(\d{4})\b", re.IGNORECASE)
PAN_RE = re.compile(r"\b([A-Z]{5}\d{4}[A-Z])\b")
AADHAAR_RE = re.compile(r"\b(\d{4}\s?\d{4}\s?\d{4})\b")
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
IFSC_RE = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
MOBILE_RE = re.compile(r"(?:\+91[\s-]?)?([6-9]\d{9})\b")


def _hmac(value: str) -> str:
    key = (settings.hmac_secret or settings.jwt_secret).encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class Redaction:
    text: str
    flags: dict[str, bool] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)


def redact_text(text: str | None) -> Redaction:
    src = text or ""
    flags = {
        "otp_like_pattern": False,
        "account_last4_mentioned": False,
        "pan_mentioned": False,
        "aadhaar_mentioned": False,
        "card_mentioned": False,
        "ifsc_mentioned": False,
        "mobile_mentioned": False,
    }
    tokens: dict[str, str] = {}

    out = src
    out = OTP_RE.sub(lambda m: (flags.__setitem__("otp_like_pattern", True), "[OTP]")[1], out)
    out = BARE_LAST4_RE.sub(
        lambda m: (
            flags.__setitem__("account_last4_mentioned", True),
            tokens.__setitem__("acct_last4", _hmac(m.group(1))),
            "[ACCT_LAST4]",
        )[-1],
        out,
    )
    out = LAST4_RE.sub(
        lambda m: (
            flags.__setitem__("account_last4_mentioned", True),
            tokens.__setitem__("acct_last4", _hmac(m.group(1))),
            "[ACCT_LAST4]",
        )[-1],
        out,
    )
    out = PAN_RE.sub(lambda m: (flags.__setitem__("pan_mentioned", True), "[PAN]")[1], out)
    out = AADHAAR_RE.sub(lambda m: (flags.__setitem__("aadhaar_mentioned", True), "[AADHAAR]")[1], out)
    out = IFSC_RE.sub(lambda m: (flags.__setitem__("ifsc_mentioned", True), "[IFSC]")[1], out)
    out = MOBILE_RE.sub(lambda m: (flags.__setitem__("mobile_mentioned", True), "[MOBILE]")[1], out)
    out = CARD_RE.sub(lambda m: (flags.__setitem__("card_mentioned", True), "[CARD]")[1], out)
    return Redaction(text=out, flags=flags, tokens=tokens)


def evidence_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
