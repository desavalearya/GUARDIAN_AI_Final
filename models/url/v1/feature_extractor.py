import math
import re
from functools import lru_cache
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import tldextract

FEATURE_NAMES = [
    "canon_length", "domain_length", "path_length", "query_length",
    "num_dots", "num_subdomains", "num_digits", "num_digits_in_host",
    "num_special_chars", "num_slashes", "num_question_marks",
    "num_equals_signs", "num_hyphens", "num_hyphens_in_host",
    "num_underscores", "num_at_symbols", "num_percent", "has_ip_address",
    "num_suspicious_keywords", "url_entropy", "host_entropy",
    "has_suspicious_tld", "digit_ratio", "subdomain_length_avg",
    "path_depth", "num_params", "has_punycode", "is_shortener",
    "brand_spoof", "has_double_slash", "hex_ratio", "tld_length",
    "longest_label_len", "has_suspicious_ext", "vowel_ratio_host",
    "dots_in_path", "is_common_domain"
]

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'tk', 'ml', 'ga', 'cf', 'gq', 'fit', 'buzz',
    'click', 'rest', 'ru', 'cn', 'bid', 'loan', 'racing', 'download'
}

SHORTENERS = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'cutt.ly', 'rebrand.ly', 'tiny.cc'
}

PROTECTED_BRANDS = {
    'sbi', 'onlinesbi', 'hdfc', 'hdfcbank', 'icici', 'icicibank', 'paytm',
    'phonepe', 'bhim', 'epfindia', 'uidai', 'incometax', 'google', 'microsoft',
    'apple', 'paypal', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp'
}

COMMON_DOMAINS = {
    'google.com', 'microsoft.com', 'microsoftonline.com', 'live.com', 'office.com',
    'apple.com', 'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com',
    'uidai.gov.in', 'incometax.gov.in', 'epfindia.gov.in', 'upi.npci.org.in',
    'paytm.com', 'phonepe.com', 'nic.in', 'gov.in'
}

SUSPICIOUS_KEYWORDS = {
    'login', 'signin', 'verify', 'verification', 'update', 'secure', 'account',
    'banking', 'confirm', 'password', 'credential', 'support', 'wallet', 'kyc',
    'auth', 'token', 'admin', 'service'
}

SUSPICIOUS_EXTENSIONS = {'.exe', '.scr', '.apk', '.bat', '.cmd', '.zip', '.rar', '.sh', '.msi', '.vbs'}
IP_REGEX = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

_TLD_PARSER = tldextract.TLDExtract(cache_dir='/tmp/tld_cache')

@lru_cache(maxsize=50000)
def cached_tld_extract(host: str):
    return _TLD_PARSER(host)

def normalize_typosquat(text: str) -> str:
    mapping = {'1': 'l', '0': 'o', '5': 's', '8': 'b', '@': 'a', 'vv': 'w'}
    for char, repl in mapping.items():
        text = text.replace(char, repl)
    return text

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)

def extract_url_features(url: str) -> dict:
    url_str = str(url).strip()
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'http://' + url_str

    try:
        parsed = urlparse(url_str)
        host = parsed.netloc.split(':')[0].lower()
        path = parsed.path
        query = parsed.query
    except Exception:
        host, path, query = '', '', ''

    ext = cached_tld_extract(host)
    subdomain = ext.subdomain.lower() if ext.subdomain else ''
    reg_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else ext.domain.lower()
    suffix = ext.suffix.lower() if ext.suffix else ''

    canon_len = len(url_str)
    domain_len = len(host)
    path_len = len(path)
    query_len = len(query)

    num_dots = url_str.count('.')
    sub_labels = [s for s in subdomain.split('.') if s]
    num_subdomains = len(sub_labels)

    num_digits = sum(c.isdigit() for c in url_str)
    num_digits_in_host = sum(c.isdigit() for c in host)
    num_special_chars = sum(c in "-_.~!*\'();:@&=+$,/?%#[]" for c in url_str)

    num_slashes = url_str.count('/')
    num_question_marks = url_str.count('?')
    num_equals_signs = url_str.count('=')
    num_hyphens = url_str.count('-')
    num_hyphens_in_host = host.count('-')
    num_underscores = url_str.count('_')
    num_at_symbols = url_str.count('@')
    num_percent = url_str.count('%')

    has_ip = 1 if IP_REGEX.match(host) else 0

    url_lower = url_str.lower()
    num_susp_kw = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    url_ent = shannon_entropy(url_str)
    host_ent = shannon_entropy(host)

    has_susp_tld = 1 if suffix in SUSPICIOUS_TLDS else 0
    digit_ratio = num_digits / max(canon_len, 1)

    sub_len_avg = (sum(len(s) for s in sub_labels) / max(num_subdomains, 1)) if num_subdomains > 0 else 0.0
    path_depth = len([p for p in path.split('/') if p])
    num_params = len(query.split('&')) if query else 0

    has_punycode = 1 if 'xn--' in host else 0
    is_shortener = 1 if host in SHORTENERS or reg_domain in SHORTENERS else 0

    normalized_url = normalize_typosquat(url_lower)
    brand_spoofed = 0
    for b in PROTECTED_BRANDS:
        if b in url_lower or b in normalized_url:
            if b not in reg_domain:
                brand_spoofed = 1
                break

    has_double_slash = 1 if '//' in path else 0
    hex_chars = len(re.findall(r'%[0-9a-fA-F]{2}', url_str)) * 3
    hex_ratio = hex_chars / max(canon_len, 1)

    tld_len = len(suffix)
    host_labels = [h for h in host.split('.') if h]
    longest_label = max((len(h) for h in host_labels), default=0)

    has_susp_ext = 0
    lower_path = path.lower()
    for ext_candidate in SUSPICIOUS_EXTENSIONS:
        if lower_path.endswith(ext_candidate):
            has_susp_ext = 1
            break

    vowels = sum(c in 'aeiou' for c in host)
    vowel_ratio = vowels / max(domain_len, 1)
    dots_in_path = path.count('.')
    is_common = 1 if reg_domain in COMMON_DOMAINS else 0

    return {
        "canon_length": canon_len,
        "domain_length": domain_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_dots": num_dots,
        "num_subdomains": num_subdomains,
        "num_digits": num_digits,
        "num_digits_in_host": num_digits_in_host,
        "num_special_chars": num_special_chars,
        "num_slashes": num_slashes,
        "num_question_marks": num_question_marks,
        "num_equals_signs": num_equals_signs,
        "num_hyphens": num_hyphens,
        "num_hyphens_in_host": num_hyphens_in_host,
        "num_underscores": num_underscores,
        "num_at_symbols": num_at_symbols,
        "num_percent": num_percent,
        "has_ip_address": has_ip,
        "num_suspicious_keywords": num_susp_kw,
        "url_entropy": round(url_ent, 4),
        "host_entropy": round(host_ent, 4),
        "has_suspicious_tld": has_susp_tld,
        "digit_ratio": round(digit_ratio, 4),
        "subdomain_length_avg": round(sub_len_avg, 2),
        "path_depth": path_depth,
        "num_params": num_params,
        "has_punycode": has_punycode,
        "is_shortener": is_shortener,
        "brand_spoof": brand_spoofed,
        "has_double_slash": has_double_slash,
        "hex_ratio": round(hex_ratio, 4),
        "tld_length": tld_len,
        "longest_label_len": longest_label,
        "has_suspicious_ext": has_susp_ext,
        "vowel_ratio_host": round(vowel_ratio, 4),
        "dots_in_path": dots_in_path,
        "is_common_domain": is_common
    }

def featurize_dataframe(urls: list[str]) -> pd.DataFrame:
    rows = [extract_url_features(u) for u in urls]
    return pd.DataFrame(rows)[FEATURE_NAMES]
