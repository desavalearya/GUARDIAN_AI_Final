"""Scan in RAM, persist tokens/flags — never OTP / last-4 / PAN / cloud secrets."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from backend.config import settings

OTP_RE = re.compile(r"\b(\d{6})\b")
LAST4_RE = re.compile(r"\b(?:a/?c|account|ending|xxxx|xx)\D{0,12}(\d{4})\b", re.IGNORECASE)
BARE_LAST4_RE = re.compile(r"\bending\s+(\d{4})\b", re.IGNORECASE)
PAN_RE = re.compile(r"\b([A-Z]{5}\d{4}[A-Z])\b")
AADHAAR_RE = re.compile(r"\b(\d{4}\s?\d{4}\s?\d{4})\b")
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
IFSC_RE = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
MOBILE_RE = re.compile(r"(?:\+91[\s-]?)?([6-9]\d{9})\b")
AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)
JWT_RE = re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b")
QUERY_SECRET_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "otp",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "key",
    "auth",
    "session",
    "code",
}


def _hmac(value: str) -> str:
    key = settings.hmac_secret.encode("utf-8")
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
        "aws_key_mentioned": False,
        "private_key_mentioned": False,
        "jwt_mentioned": False,
    }
    tokens: dict[str, str] = {}

    out = src
    out = PRIVATE_KEY_RE.sub(
        lambda _m: (flags.__setitem__("private_key_mentioned", True), "[PRIVATE_KEY]")[1],
        out,
    )
    out = AWS_KEY_RE.sub(
        lambda m: (
            flags.__setitem__("aws_key_mentioned", True),
            tokens.__setitem__("aws_key", _hmac(m.group(1))),
            "[AWS_KEY]",
        )[-1],
        out,
    )
    out = JWT_RE.sub(
        lambda m: (
            flags.__setitem__("jwt_mentioned", True),
            tokens.__setitem__("jwt", _hmac(m.group(1)[:48])),
            "[JWT]",
        )[-1],
        out,
    )
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


def redact_url(url: str | None) -> str:
    """Persist host/path; scrub credential-bearing query values and embedded secrets."""
    raw = (url or "").strip()
    if not raw:
        return ""
    redacted = redact_text(raw).text
    try:
        parts = urlsplit(redacted if "://" in redacted else "http://" + redacted)
        query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if key.lower() in QUERY_SECRET_KEYS:
                query.append((key, "[REDACTED]"))
            else:
                query.append((key, redact_text(value).text))
        cleaned = urlunsplit(
            (
                parts.scheme if "://" in redacted else "",
                parts.netloc,
                parts.path,
                urlencode(query),
                "",
            )
        )
        if "://" not in redacted and cleaned.startswith("http://"):
            cleaned = cleaned[len("http://") :]
        return cleaned
    except Exception:
        return redacted


def mask_local_part(address: str | None) -> str:
    addr = (address or "").strip()
    if "@" not in addr:
        return addr
    local, domain = addr.split("@", 1)
    if len(local) <= 2:
        masked = "*" * len(local)
    else:
        masked = local[0] + ("*" * (len(local) - 2)) + local[-1]
    return f"{masked}@{domain}"


def sanitize_evidence(value: Any, depth: int = 0) -> Any:
    """Recursively redact string leaves in detector evidence before persistence."""
    if depth > 6:
        return "[truncated]"
    if isinstance(value, str):
        return redact_text(value).text
    if isinstance(value, list):
        return [sanitize_evidence(item, depth + 1) for item in value[:80]]
    if isinstance(value, dict):
        out = {}
        for key, item in list(value.items())[:80]:
            key_l = str(key).lower()
            if key_l in {"otp", "last4", "pan", "aadhaar", "card", "password", "secret", "token"}:
                out[str(key)] = True if isinstance(item, (str, int, float, bool)) else "[REDACTED]"
            elif key_l in {"raw_url", "url", "href"}:
                out[str(key)] = redact_url(str(item))
            else:
                out[str(key)] = sanitize_evidence(item, depth + 1)
        return out
    return value


def evidence_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
