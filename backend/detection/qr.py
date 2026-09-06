"""QR decode → URLs for the same heuristic URL pipeline.

OCR/QR libraries are optional so the gateway still runs without a rebuild.
"""

from __future__ import annotations

import logging
import re
from html import unescape

from backend.email.parser import ParsedAttachment, ParsedEmail, ParsedUrl, _domain

log = logging.getLogger(__name__)

HTTP_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
IMG_SRC_RE = re.compile(r"""<img[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
IMG_ALT_RE = re.compile(
    r"""<img[^>]+(?:alt|title)=["']([^"']+)["']""",
    re.IGNORECASE,
)


def _decode_with_pyzbar(payload: bytes) -> list[str]:
    try:
        from io import BytesIO

        from PIL import Image
        from pyzbar.pyzbar import decode
    except ImportError:
        return []
    try:
        img = Image.open(BytesIO(payload))
        return [item.data.decode("utf-8", errors="replace") for item in decode(img)]
    except Exception as exc:  # noqa: BLE001
        log.debug("pyzbar decode failed: %s", exc)
        return []


def _decode_with_cv2(payload: bytes) -> list[str]:
    try:
        import cv2
        import numpy as np
    except ImportError:
        return []
    try:
        arr = np.frombuffer(payload, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return []
        detector = cv2.QRCodeDetector()
        ok, decoded, _, _ = detector.detectAndDecodeMulti(img)
        if ok and decoded:
            return [text for text in decoded if text]
        data, _, _ = detector.detectAndDecode(img)
        return [data] if data else []
    except Exception as exc:  # noqa: BLE001
        log.debug("cv2 QR decode failed: %s", exc)
        return []


def decode_image_payload(payload: bytes) -> list[str]:
    texts = _decode_with_pyzbar(payload)
    if not texts:
        texts = _decode_with_cv2(payload)
    urls: list[str] = []
    for text in texts:
        urls.extend(HTTP_RE.findall(text or ""))
        if text.strip().startswith("http"):
            urls.append(text.strip())
    seen: set[str] = set()
    out = []
    for url in urls:
        url = url.rstrip(").,;]")
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _is_image(att: ParsedAttachment) -> bool:
    name = att.filename.lower()
    return att.mime_type.startswith("image/") or name.endswith(
        (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")
    )


def collect_qr_urls(parsed: ParsedEmail) -> tuple[list[ParsedUrl], dict]:
    """Return QR/HTML image URLs and a report for the image_qr detector."""
    found: list[ParsedUrl] = []
    images = [a for a in parsed.attachments if _is_image(a)]
    decoded_from: list[str] = []
    decoder = "none"

    for att in images:
        urls = decode_image_payload(att.payload)
        if urls:
            decoder = "pyzbar_or_cv2"
            decoded_from.append(att.filename)
        for url in urls:
            found.append(ParsedUrl(raw_url=url, source="qr", domain=_domain(url)))

    html = unescape(parsed.body_html or "")
    for alt in IMG_ALT_RE.findall(html):
        for url in HTTP_RE.findall(alt):
            url = url.rstrip(").,;]")
            found.append(ParsedUrl(raw_url=url, source="qr_alt", domain=_domain(url)))
            if decoder == "none":
                decoder = "img-alt"

    report = {
        "image_count": len(images) + len(IMG_SRC_RE.findall(html)),
        "qr_url_count": len(found),
        "decoded_from": decoded_from,
        "decoder": decoder,
        "urls": [u.raw_url for u in found],
    }
    return found, report


def enrich_parsed_with_qr(parsed: ParsedEmail) -> dict:
    """Append decoded QR URLs onto parsed.urls so persist + URL scoring see them."""
    extra, report = collect_qr_urls(parsed)
    have = {u.raw_url for u in parsed.urls}
    for item in extra:
        if item.raw_url not in have:
            parsed.urls.append(item)
            have.add(item.raw_url)
    return report
