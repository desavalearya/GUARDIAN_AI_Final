"""Submit outbound mail through Postfix (DKIM-signed) after Guardian allows it."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from backend.config import settings

log = logging.getLogger(__name__)


def submit_via_postfix(
    sender: str,
    recipient: str,
    subject: str,
    body: str,
) -> dict:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    host = settings.postfix_host
    port = settings.postfix_submission_port
    try:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo()
            # Docker network submission is trusted via mynetworks
            smtp.send_message(msg)
        return {"ok": True, "via": f"{host}:{port}"}
    except Exception as exc:
        log.exception("postfix submit failed")
        return {"ok": False, "error": str(exc)}
