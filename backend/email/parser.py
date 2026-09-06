from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html import unescape
from urllib.parse import urlparse


URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
HTML_HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)


@dataclass
class ParsedUrl:
    raw_url: str
    source: str
    domain: str


@dataclass
class ParsedAttachment:
    filename: str
    mime_type: str
    payload: bytes
    sha256: str
    size: int


@dataclass
class ParsedEmail:
    sender_address: str
    sender_display_name: str
    recipient_address: str
    subject: str
    body_plain: str
    body_html: str | None
    raw_headers: str
    raw_message: str
    urls: list[ParsedUrl] = field(default_factory=list)
    attachments: list[ParsedAttachment] = field(default_factory=list)
    content_hash_sha256: str = ""


def _domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _collect_urls(text: str, source: str) -> list[ParsedUrl]:
    seen: set[str] = set()
    out: list[ParsedUrl] = []
    for match in URL_RE.findall(text or ""):
        url = match.rstrip(").,;]")
        if url not in seen:
            seen.add(url)
            out.append(ParsedUrl(raw_url=url, source=source, domain=_domain(url)))
    return out


def parse_raw_email(raw: bytes | str, default_recipient: str = "user@example.com") -> ParsedEmail:
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", errors="replace")
        raw_text = raw
    else:
        raw_bytes = raw
        raw_text = raw.decode("utf-8", errors="replace")

    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    display, addr = parseaddr(msg.get("From", ""))
    _to_display, to_addr = parseaddr(msg.get("To", "") or default_recipient)

    body_plain = ""
    body_html = None
    attachments: list[ParsedAttachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if ctype == "text/plain" and "attachment" not in disp:
                payload = part.get_content()
                body_plain += payload if isinstance(payload, str) else ""
            elif ctype == "text/html" and "attachment" not in disp:
                payload = part.get_content()
                body_html = payload if isinstance(payload, str) else None
            elif "attachment" in disp or part.get_filename():
                filename = part.get_filename() or "unnamed"
                data = part.get_payload(decode=True) or b""
                attachments.append(
                    ParsedAttachment(
                        filename=filename,
                        mime_type=ctype,
                        payload=data,
                        sha256=hashlib.sha256(data).hexdigest(),
                        size=len(data),
                    )
                )
    else:
        payload = msg.get_content()
        if msg.get_content_type() == "text/html":
            body_html = payload if isinstance(payload, str) else None
            body_plain = re.sub(r"<[^>]+>", " ", body_html or "")
        else:
            body_plain = payload if isinstance(payload, str) else raw_text

    urls = _collect_urls(body_plain, "body_text")
    if body_html:
        for href in HTML_HREF_RE.findall(unescape(body_html)):
            if href.startswith("http"):
                urls.append(ParsedUrl(raw_url=href, source="body_html", domain=_domain(href)))

    unique: dict[str, ParsedUrl] = {}
    for item in urls:
        unique[item.raw_url] = item

    normalized = " ".join((body_plain or "").lower().split())
    content_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    return ParsedEmail(
        sender_address=(addr or "").lower(),
        sender_display_name=display or "",
        recipient_address=(to_addr or default_recipient).lower(),
        subject=str(msg.get("Subject") or ""),
        body_plain=body_plain.strip(),
        body_html=body_html,
        raw_headers="\n".join(f"{k}: {v}" for k, v in msg.items()),
        raw_message=raw_text,
        urls=list(unique.values()),
        attachments=attachments,
        content_hash_sha256=content_hash,
    )


def build_rfc822(
    sender: str,
    recipient: str,
    subject: str,
    body: str,
) -> str:
    return (
        f"From: {sender}\r\n"
        f"To: {recipient}\r\n"
        f"Subject: {subject}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"{body}\r\n"
    )
