"""Offline GeoLite2 City + ASN lookups. Never described as attacker GPS."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from backend.config import settings

log = logging.getLogger(__name__)

_city = None
_asn = None
_city_failed = False
_asn_failed = False


def _data_root() -> Path:
    return Path(settings.data_dir)


def _find_db(*names: str) -> Path | None:
    root = _data_root()
    for name in names:
        direct = root / "geoip" / name
        if direct.exists():
            return direct
    geo = root / "geoip"
    if geo.exists():
        for path in geo.rglob("*.mmdb"):
            if any(key in path.name for key in names):
                return path
    return None


def _open_db(kind: str):
    try:
        import maxminddb
    except ImportError:
        log.warning("maxminddb is not installed; GeoLite2 lookups disabled")
        return None
    if kind == "city":
        path = _find_db("GeoLite2-City.mmdb")
    else:
        path = _find_db("GeoLite2-ASN.mmdb")
    if path is None:
        log.warning("GeoLite2 %s database not found under %s", kind, _data_root())
        return None
    return maxminddb.open_database(str(path))


def lookup_city(ip: str) -> dict[str, Any]:
    global _city, _city_failed
    if _city_failed:
        return {}
    if _city is None:
        _city = _open_db("city")
        if _city is None:
            _city_failed = True
            return {}
    try:
        rec = _city.get(ip) or {}
    except Exception as exc:  # noqa: BLE001
        log.debug("city lookup failed for %s: %s", ip, exc)
        return {}
    country = (rec.get("country") or {}).get("names") or {}
    city = (rec.get("city") or {}).get("names") or {}
    loc = rec.get("location") or {}
    subdiv = ""
    subs = rec.get("subdivisions") or []
    if subs:
        subdiv = ((subs[0] or {}).get("names") or {}).get("en") or ""
    return {
        "country": country.get("en") or "",
        "country_iso": (rec.get("country") or {}).get("iso_code") or "",
        "region": subdiv,
        "city": city.get("en") or "",
        "latitude": loc.get("latitude"),
        "longitude": loc.get("longitude"),
        "accuracy_radius_km": loc.get("accuracy_radius"),
        "timezone": loc.get("time_zone") or "",
    }


def lookup_asn(ip: str) -> dict[str, Any]:
    global _asn, _asn_failed
    if _asn_failed:
        return {}
    if _asn is None:
        _asn = _open_db("asn")
        if _asn is None:
            _asn_failed = True
            return {}
    try:
        rec = _asn.get(ip) or {}
    except Exception as exc:  # noqa: BLE001
        log.debug("asn lookup failed for %s: %s", ip, exc)
        return {}
    return {
        "asn": rec.get("autonomous_system_number"),
        "aso": rec.get("autonomous_system_organization") or "",
    }
