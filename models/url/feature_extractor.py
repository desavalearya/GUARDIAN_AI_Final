
"""Canonical lexical URL features. Ignore scheme/www/raw length. Flag well-known domains."""
import re
import math
from collections import Counter
from urllib.parse import urlparse, unquote

FEATURE_NAMES = [
    "canon_length", "domain_length", "path_length", "query_length",
    "num_dots", "num_subdomains", "num_digits", "num_digits_in_host",
    "num_special_chars", "num_slashes", "num_question_marks", "num_equals_signs",
    "num_hyphens", "num_hyphens_in_host", "num_underscores", "num_at_symbols",
    "num_percent", "has_ip_address", "num_suspicious_keywords", "url_entropy",
    "host_entropy", "has_suspicious_tld", "digit_ratio", "subdomain_length_avg",
    "path_depth", "num_params", "has_punycode", "is_shortener", "brand_spoof",
    "has_double_slash", "hex_ratio", "tld_length", "longest_label_len",
    "has_suspicious_ext", "vowel_ratio_host", "dots_in_path", "is_common_domain",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "bank",
    "signin", "security", "webscr", "ebayisapi", "paypal", "password",
    "credential", "suspend", "unlock", "authenticate", "wallet", "billing",
    "invoice", "urgent", "alert", "support", "recover", "validate",
    "limited", "unusual", "restore", "office365", "outlook", "dhl", "fedex",
    "refund", "shared", "document", "attachment", "metamask", "crypto",
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "loan", "download", "review", "country", "stream", "gdn", "zip",
    "mov", "cam", "surf", "quest", "monster", "cyou", "rest", "icu",
    "buzz", "kim", "men", "date", "faith", "win", "bid",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "lnkd.in", "s.id",
}

BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "facebook", "instagram",
    "whatsapp", "netflix", "outlook", "office", "linkedin", "twitter",
    "bankofamerica", "wellsfargo", "chase", "dhl", "fedex", "ups", "adobe",
    "dropbox", "icloud", "appleid", "binance", "metamask", "coinbase",
]

COMMON_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "gstatic.com", "googleusercontent.com",
    "microsoft.com", "office.com", "live.com", "outlook.com", "msn.com", "bing.com",
    "github.com", "githubusercontent.com", "amazon.com", "amazonaws.com",
    "apple.com", "icloud.com", "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com", "linkedin.com", "netflix.com", "reddit.com",
    "wikipedia.org", "yahoo.com", "cloudflare.com", "zoom.us", "dropbox.com",
    "adobe.com", "paypal.com", "ebay.com", "walmart.com", "spotify.com",
    "tiktok.com", "openai.com", "chatgpt.com",
}

SUSPICIOUS_EXTS = {".exe", ".zip", ".rar", ".apk", ".scr", ".js", ".vbs", ".iso"}
SECOND_LEVEL_CC = {"co", "com", "net", "org", "gov", "ac"}

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")
_VOWELS = set("aeiou")


def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _safe_parse(url):
    raw = (url or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        return urlparse(raw)
    except Exception:
        return None


def _host_from_parsed(parsed):
    if parsed is None:
        return ""
    try:
        host = parsed.hostname
        host = host.lower() if host else ""
    except Exception:
        netloc = (parsed.netloc or "").lower()
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[-1]
        if netloc.startswith("["):
            end = netloc.find("]")
            host = netloc[1:end] if end != -1 else netloc.strip("[]")
        else:
            host = netloc.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def _registrable_domain(host):
    if not host:
        return ""
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL_CC:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _looks_like_ip(host):
    if not host:
        return False
    return bool(_IPV4_RE.match(host.split("%")[0]))


def _brand_spoof(host):
    if not host:
        return 0
    h = host.lower()
    for b in BRANDS:
        if b not in h:
            continue
        if h == b or h.endswith("." + b + ".com") or h.endswith(b + ".com"):
            continue
        if h.endswith("." + b + ".net") or h.endswith(b + ".net"):
            continue
        return 1
    return 0


def extract_features(url):
    try:
        original = url if isinstance(url, str) else ("" if url is None else str(url))
        original = original.strip()
        parsed = _safe_parse(original)

        host = _host_from_parsed(parsed)
        path = (parsed.path or "") if parsed else ""
        query = (parsed.query or "") if parsed else ""
        canon = host + path + (("?" + query) if query else "")

        try:
            decoded = unquote(original)
        except Exception:
            decoded = original

        labels = [p for p in host.split(".") if p]
        num_subdomains = max(len(labels) - 2, 0)
        tld = labels[-1] if labels else ""
        n = len(canon)
        num_digits = sum(ch.isdigit() for ch in canon)
        num_digits_host = sum(ch.isdigit() for ch in host)
        hexes = _HEX_RE.findall(original)
        vowels = sum(ch in _VOWELS for ch in host)
        path_l = path.lower()
        root = _registrable_domain(host)

        return {
            "canon_length": n,
            "domain_length": len(host),
            "path_length": len(path),
            "query_length": len(query),
            "num_dots": canon.count("."),
            "num_subdomains": num_subdomains,
            "num_digits": num_digits,
            "num_digits_in_host": num_digits_host,
            "num_special_chars": len(re.findall(r"[^a-zA-Z0-9]", canon)),
            "num_slashes": path.count("/"),
            "num_question_marks": query.count("?") + (1 if query else 0),
            "num_equals_signs": query.count("="),
            "num_hyphens": canon.count("-"),
            "num_hyphens_in_host": host.count("-"),
            "num_underscores": canon.count("_"),
            "num_at_symbols": original.count("@"),
            "num_percent": original.count("%"),
            "has_ip_address": int(_looks_like_ip(host)),
            "num_suspicious_keywords": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in decoded.lower()),
            "url_entropy": _shannon_entropy(canon),
            "host_entropy": _shannon_entropy(host),
            "has_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
            "digit_ratio": (num_digits / n) if n else 0.0,
            "subdomain_length_avg": (
                sum(len(p) for p in labels[:-2]) / num_subdomains if num_subdomains else 0.0
            ),
            "path_depth": max(len([p for p in path.split("/") if p]), 0),
            "num_params": len([p for p in query.split("&") if p]) if query else 0,
            "has_punycode": int("xn--" in host),
            "is_shortener": int(host in SHORTENERS or root in SHORTENERS),
            "brand_spoof": _brand_spoof(host),
            "has_double_slash": int("//" in path),
            "hex_ratio": (3 * len(hexes) / max(len(original), 1)),
            "tld_length": len(tld),
            "longest_label_len": max((len(p) for p in labels), default=0),
            "has_suspicious_ext": int(any(path_l.endswith(ext) for ext in SUSPICIOUS_EXTS)),
            "vowel_ratio_host": (vowels / len(host)) if host else 0.0,
            "dots_in_path": path.count("."),
            "is_common_domain": int(root in COMMON_DOMAINS),
        }
    except Exception:
        return {k: 0.0 for k in FEATURE_NAMES}


def featurize_dataframe(urls, feature_names=None):
    import numpy as np
    import pandas as pd
    names = feature_names or FEATURE_NAMES
    urls_list = urls.tolist() if hasattr(urls, "tolist") else list(urls)
    n = len(urls_list)
    mat = np.empty((n, len(names)), dtype=np.float32)
    for i, u in enumerate(urls_list):
        feats = extract_features(u)
        mat[i, :] = [feats[name] for name in names]
        if i and i % 100000 == 0:
            print(f"  featurized {i:,} / {n:,}")
    return pd.DataFrame(mat, columns=names)
