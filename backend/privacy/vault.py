"""Encrypted evidence vault. Raw mail is never stored in cleartext."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken

from backend.config import settings


def _fernet() -> Fernet:
    key = hashlib.sha256((settings.vault_secret or settings.jwt_secret).encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_raw(raw: bytes) -> bytes:
    return _fernet().encrypt(raw)


def decrypt_raw(blob: bytes) -> bytes:
    try:
        return _fernet().decrypt(blob)
    except InvalidToken as exc:
        raise ValueError("vault unlock failed") from exc


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
