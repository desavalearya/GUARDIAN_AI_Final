"""Opaque click-time URL rewriting without persisting destination URLs."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time

from cryptography.fernet import Fernet, InvalidToken

from backend.config import settings

URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.I)


def _fernet() -> Fernet:
    key = hashlib.sha256(settings.url_rewrite_secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def token_for_url(url: str) -> str:
    payload = json.dumps(
        {"url": url, "expires": int(time.time()) + settings.url_rewrite_ttl_seconds},
        separators=(",", ":"),
    ).encode("utf-8")
    return _fernet().encrypt(payload).decode("ascii")


def url_from_token(token: str) -> str:
    try:
        payload = json.loads(_fernet().decrypt(token.encode("ascii")).decode("utf-8"))
    except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid or expired link token") from exc
    if int(payload.get("expires") or 0) < int(time.time()):
        raise ValueError("Link token expired")
    url = str(payload.get("url") or "")
    if not url.startswith(("http://", "https://")):
        raise ValueError("Unsupported destination")
    return url


def rewrite_text_urls(text: str) -> str:
    if not settings.url_rewrite_enabled:
        return text
    base = settings.public_api_url.rstrip("/")

    def replace(match: re.Match[str]) -> str:
        url = match.group(0)
        if url.startswith(base + "/r/"):
            return url
        trailing = ""
        while url and url[-1] in ".,);]":
            trailing = url[-1] + trailing
            url = url[:-1]
        return f"{base}/r/{token_for_url(url)}{trailing}"

    return URL_RE.sub(replace, text)
