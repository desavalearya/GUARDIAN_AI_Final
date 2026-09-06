"""Probable originating infrastructure — never 'attacker city' or GPS track."""

from __future__ import annotations

from backend.detection.relay import header_anomalies, parse_relay_path
from backend.detection.types import DetectorOutput, verdict_from_score as _verdict
from backend.email.parser import ParsedEmail
from backend.intel.geoip import lookup_asn, lookup_city
from backend.intel.lists import cached_whois, classify_infra


def run_origin_infra(parsed: ParsedEmail) -> DetectorOutput:
    path = parse_relay_path(parsed.raw_headers)
    anomalies = header_anomalies(parsed.raw_headers, parsed.sender_address)
    ip = path.earliest_public_ip
    city = lookup_city(ip) if ip else {}
    asn_rec = lookup_asn(ip) if ip else {}
    asn = asn_rec.get("asn")
    aso = asn_rec.get("aso") or ""
    infra_class = classify_infra(ip, int(asn) if asn else None, aso)

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
                "disclaimer": "No public relay IP. This is not an attacker location.",
            },
            model_version="origin-geo-v1",
        )

    if infra_class == "tor_exit":
        score = max(score, 0.72)
        reasons.append("relay IP is on the offline TOR-exit seed list")
    elif infra_class == "vpn":
        score = max(score, 0.55)
        reasons.append("relay ASN matches a known VPN/hosting-privacy network")
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
                "note": "MaxMind GeoLite2 city-level estimate, often a datacenter.",
            },
            "header_anomalies": anomalies,
            "whois_sender": whois,
            "whois_urls": url_whois,
            "hop_count": len(path.hops),
            "disclaimer": "Probable originating infrastructure only — not an attacker location or exact track.",
        },
        model_version="origin-geo-v1",
    )
