"""Probable originating infrastructure — never 'attacker city' or GPS track."""

from __future__ import annotations

import re

from backend.detection.relay import header_anomalies, header_values, parse_relay_path
from backend.detection.types import DetectorOutput, verdict_from_score as _verdict
from backend.email.parser import ParsedEmail
from backend.intel.geoip import lookup_asn, lookup_city
from backend.intel.lists import cached_whois, classify_infra

WEBMAIL_SENDERS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "yahoo.co.in",
}
WEBMAIL_HOST_MARKS = (
    "google.com",
    "googlemail.com",
    "mail-sor-",
    "outlook.com",
    "protection.outlook.com",
    "yahoo.com",
    "yahoodns.net",
)
WEBMAIL_ASNS = {15169, 8075, 36647, 26101}  # Google, Microsoft, Yahoo-ish


def _sender_domain(address: str) -> str:
    return address.split("@")[-1].lower() if "@" in (address or "") else ""


def _looks_like_webmail(raw_headers: str, sender: str, asn: int | None) -> bool:
    domain = _sender_domain(sender)
    blob = (raw_headers or "").lower()
    host_hit = any(mark in blob for mark in WEBMAIL_HOST_MARKS)
    if domain in WEBMAIL_SENDERS and host_hit:
        return True
    if domain in WEBMAIL_SENDERS and asn in WEBMAIL_ASNS:
        return True
    return False


def _date_tz_offset(raw_headers: str) -> str:
    for value in header_values(raw_headers, "date"):
        match = re.search(r"([+-]\d{4})\b", value or "")
        if match:
            return match.group(1)
    return ""


def run_origin_infra(parsed: ParsedEmail) -> DetectorOutput:
    path = parse_relay_path(parsed.raw_headers)
    anomalies = header_anomalies(parsed.raw_headers, parsed.sender_address)
    ip = path.earliest_public_ip
    city = lookup_city(ip) if ip else {}
    asn_rec = lookup_asn(ip) if ip else {}
    asn = asn_rec.get("asn")
    aso = asn_rec.get("aso") or ""
    webmail = _looks_like_webmail(parsed.raw_headers, parsed.sender_address, int(asn) if asn else None)
    infra_class = "webmail" if webmail else classify_infra(ip, int(asn) if asn else None, aso)
    date_tz = _date_tz_offset(parsed.raw_headers)

    sender_domain = parsed.sender_address.split("@")[-1].lower() if "@" in parsed.sender_address else ""
    whois = cached_whois(sender_domain)
    url_whois = []
    for item in parsed.urls:
        rec = cached_whois(item.domain)
        if rec:
            url_whois.append({"domain": item.domain, **rec})

    score = 0.08
    reasons: list[str] = []
    if not ip:
        if anomalies:
            score = 0.35
            reasons.extend(anomalies)
        return DetectorOutput(
            detector_name="origin_infra",
            raw_score=round(score, 3),
            verdict="not_applicable" if not anomalies else _verdict(score),
            explanation=path.note
            if not anomalies
            else path.note + " Header anomalies: " + "; ".join(anomalies),
            evidence={
                "language": "probable_originating_infrastructure",
                "earliest_public_ip": None,
                "hops": [h.received for h in path.hops[:8]],
                "header_anomalies": anomalies,
                "whois_sender": whois,
                "reliable": False,
                "relay_note": path.note,
                "disclaimer": "No public relay IP. This is not an attacker location.",
            },
            model_version="origin-geo-v2",
        )

    if not path.reliable:
        score = max(score, 0.2)
        reasons.append("relay path reliability is best-effort (no trusted MTA marker)")

    if infra_class == "tor_exit":
        score = max(score, 0.72)
        reasons.append("relay IP is on the offline TOR-exit seed list")
    elif infra_class == "vpn":
        score = max(score, 0.55)
        reasons.append("relay ASN matches a known VPN/hosting-privacy network")
    elif infra_class == "webmail":
        score = max(score, 0.08)
        reasons.append(
            "relay is consumer webmail; GeoIP is the provider datacenter, not the sender's city"
        )
    elif infra_class == "cloud_hosting":
        score = max(score, 0.42)
        reasons.append("relay ASN looks like cloud/hosting infrastructure")
    elif infra_class == "hosting":
        score = max(score, 0.38)
        reasons.append("relay ASN looks like a hosting provider")

    if whois and int(whois.get("age_days") or 9999) < 60:
        score = max(score, 0.5)
        reasons.append(f"sender domain is young in WHOIS cache ({whois.get('age_days')} days)")
    for rec in url_whois:
        if int(rec.get("age_days") or 9999) < 60:
            score = max(score, 0.5)
            reasons.append(f"URL domain {rec['domain']} is young in WHOIS cache")

    if anomalies:
        score = min(0.9, score + 0.12)
        reasons.extend(anomalies)

    city_label = ", ".join(part for part in (city.get("city"), city.get("region"), city.get("country")) if part)
    asn_label = f"AS{asn} {aso}".strip() if asn else "ASN unknown"
    explanation = (
        f"Probable originating infrastructure: {ip} · {asn_label}"
        + (f" · GeoIP city-level {city_label}" if city_label else "")
        + (f" · class {infra_class}" if infra_class else "")
        + ". This is not an attacker home address."
    )
    if webmail:
        explanation += (
            " Gmail/Outlook/Yahoo Received hops are the provider's mail servers; "
            "the client city (for example Pune) is not in the headers."
        )
    if date_tz:
        explanation += f" Date header offset {date_tz} is a timezone hint only, not a city."
    if reasons:
        explanation += " Signals: " + "; ".join(reasons) + "."

    return DetectorOutput(
        detector_name="origin_infra",
        raw_score=round(min(score, 0.9), 3),
        verdict=_verdict(score),
        explanation=explanation,
        evidence={
            "language": "probable_originating_infrastructure",
            "earliest_public_ip": ip,
            "infra_class": infra_class,
            "asn": asn,
            "aso": aso,
            "geo": {
                "city": city.get("city") or "",
                "region": city.get("region") or "",
                "country": city.get("country") or "",
                "country_iso": city.get("country_iso") or "",
                "latitude": city.get("latitude"),
                "longitude": city.get("longitude"),
                "accuracy_radius_km": city.get("accuracy_radius_km"),
                "note": (
                    "Provider datacenter estimate. Consumer webmail hides the client IP."
                    if webmail
                    else "MaxMind GeoLite2 city-level estimate, often a datacenter."
                ),
            },
            "header_anomalies": anomalies,
            "whois_sender": whois,
            "whois_urls": url_whois,
            "hop_count": len(path.hops),
            "webmail": webmail,
            "date_tz_offset": date_tz,
            "reliable": path.reliable,
            "relay_note": path.note,
            "discarded_untrusted_hops": path.discarded_untrusted_prefix,
            "disclaimer": "Probable originating infrastructure only — not an attacker location or exact track. Physical attacker location: NOT ESTABLISHED.",
        },
        model_version="origin-geo-v2",
    )
