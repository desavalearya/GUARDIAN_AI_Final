"""Mirror messages into the Company B Mailpit UI for the two-server demo."""

from __future__ import annotations

import logging

import httpx

from backend.config import settings

log = logging.getLogger(__name__)


def mirror_to_mailpit(
    *,
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    sender_name: str = "Company B",
) -> dict:
    """Store a copy in Mailpit so the Company B inbox shows the same traffic."""
    url = f"{settings.mailpit_url.rstrip('/')}/api/v1/send"
    payload = {
        "From": {"Email": sender, "Name": sender_name},
        "To": [{"Email": recipient}],
        "Subject": subject,
        "Text": body,
    }
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code >= 400:
                return {"ok": False, "error": f"mailpit HTTP {resp.status_code}: {resp.text[:200]}"}
            data = resp.json() if resp.content else {}
            return {"ok": True, "id": data.get("ID") or data.get("Id")}
    except Exception as exc:
        log.warning("mailpit mirror failed: %s", exc)
        return {"ok": False, "error": str(exc)}
