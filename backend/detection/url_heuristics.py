"""Heuristic URL scoring. Does not load models/url/ (parked until a new artifact)."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from backend.email.parser import ParsedUrl

BAD_TLDS = (".xyz", ".top", ".click", ".zip", ".mov", ".country", ".gq", ".tk", ".ml", ".cf", ".ga")
ODD_SUFFIXES = (".ch.ma", ".co.cc", ".co.vu", ".cu.cc", ".za.net", ".xx.fb")
SCRIPT_PATH_RE = re.compile(r"\.(js|exe|apk|scr|vbs|bat|cmd|msi)(?:\?|$|/)", re.IGNORECASE)
AD_CLOAK = ("google_ad_format", "google_ad", "clickid=", "gclid=", "utm_redirect")
SHORTENERS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "lnkd.in",
    "rb.gy",
    "shorturl.at",
}
CAPTCHA_MARKS = ("captcha", "recaptcha", "hcaptcha", "areyouhuman", "verify-human")
LURE_WORDS = ("login", "verify", "secure", "update", "paypal", "account", "signin", "password", "wallet")
BRANDS = (
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "sbi",
    "hdfc",
    "icici",
    "axisbank",
    "paytm",
    "phonepe",
    "office",
)
SAFE_DOMAINS = {
    "google.com",
    "microsoft.com",
    "office.com",
    "gmail.com",
    "github.com",
    "wikipedia.org",
    "gov.in",
    "nic.in",
}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins, delete, sub = prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def _looks_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""))


def score_one_url(raw_url: str, domain: str) -> tuple[float, list[str]]:
    url = (raw_url or "").lower()
    host = (domain or "").lower().strip(".")
    reasons: list[str] = []
    score = 0.08

    if host in SAFE_DOMAINS or any(host.endswith(f".{d}") for d in SAFE_DOMAINS):
        return 0.05, ["known-safe-domain"]

    if any(host.endswith(tld) or tld in host for tld in BAD_TLDS):
        score = max(score, 0.7)
        reasons.append("suspicious-tld")
    if _looks_ip(host):
        score = max(score, 0.85)
        reasons.append("ip-literal-host")
    if "@" in url:
        score = max(score, 0.8)
        reasons.append("credentials-in-url")
    if url.count("-") > 4:
        score = max(score, 0.6)
        reasons.append("hyphenated-host")
    if host.startswith("xn--") or ".xn--" in host:
        score = max(score, 0.72)
        reasons.append("punycode")
    if host in SHORTENERS:
        score = max(score, 0.68)
        reasons.append("url-shortener")
    if any(mark in url for mark in CAPTCHA_MARKS):
        score = max(score, 0.7)
        reasons.append("captcha-gate")
    if any(word in url for word in LURE_WORDS):
        score = max(score, 0.75)
        reasons.append("lure-keyword")
    if any(host.endswith(suf) or host.endswith(suf.lstrip(".")) for suf in ODD_SUFFIXES):
        score = max(score, 0.8)
        reasons.append("odd-compound-tld")
    parsed = urlparse(raw_url if "://" in (raw_url or "") else "http://" + (raw_url or ""))
    if SCRIPT_PATH_RE.search(f"{parsed.path}?{parsed.query}"):
        score = max(score, 0.78)
        reasons.append("script-or-binary-path")
    if any(mark in url for mark in AD_CLOAK):
        score = max(score, 0.8)
        reasons.append("ad-cloak-params")

    labels = host.replace("-", ".").split(".")
    for brand in BRANDS:
        official = (f"{brand}.com", f"{brand}.in", f"{brand}.co.in")
        if host in official or any(host.endswith(f".{o}") for o in official):
            continue
        for label in labels:
            if not label or label == brand:
                continue
            dist = levenshtein(label, brand)
            if 0 < dist <= 2 and len(label) >= 4:
                score = max(score, 0.88)
                reasons.append(f"lookalike:{brand}")
                break
        if brand in host:
            score = max(score, 0.78)
            reasons.append(f"brand-in-unrelated-host:{brand}")

    if parsed.scheme not in ("http", "https", ""):
        score = max(score, 0.55)
        reasons.append("odd-scheme")

    return round(min(score, 0.98), 3), reasons


def score_urls(urls: list[ParsedUrl]) -> tuple[float, list[dict]]:
    details = []
    scores = []
    for item in urls:
        s, reasons = score_one_url(item.raw_url, item.domain)
        scores.append(s)
        details.append(
            {
                "url": item.raw_url,
                "domain": item.domain,
                "source": getattr(item, "source", ""),
                "score": s,
                "reasons": reasons,
            }
        )
    return (max(scores) if scores else 0.0), details
