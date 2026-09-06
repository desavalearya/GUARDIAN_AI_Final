"""Offline VPN / TOR / cloud class lists and cached WHOIS for the demo."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

from backend.config import settings

log = logging.getLogger(__name__)

CLOUD_ORG_MARKS = (
    "amazon",
    "aws",
    "google cloud",
    "google llc",
    "microsoft",
    "azure",
    "digitalocean",
    "hetzner",
    "ovh",
    "linode",
    "akamai",
    "choopa",
    "vultr",
    "contabo",
    "leaseweb",
    "m247",
    "datacamp",
    "hostinger",
    "cloudflare",
)
HOSTING_ORG_MARKS = ("host", "datacenter", "data center", "dedicated", "colocation", "server")
VPN_ORG_MARKS = ("mullvad", "nordvpn", "expressvpn", "surfshark", "proton", "private internet", "pia")


def _intel_dir() -> Path:
    return Path(settings.data_dir) / "intel"


@lru_cache(maxsize=1)
def _cloud_asns() -> set[int]:
    return _load_asn_set("cloud_asns.json")


@lru_cache(maxsize=1)
def _vpn_asns() -> set[int]:
    return _load_asn_set("vpn_asns.json")


@lru_cache(maxsize=1)
def _tor_ips() -> set[str]:
    path = _intel_dir() / "tor_exits.txt"
    if not path.exists():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


@lru_cache(maxsize=1)
def whois_cache() -> dict:
    path = _intel_dir() / "whois_cache.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning("invalid whois cache at %s", path)
        return {}


def _load_asn_set(name: str) -> set[int]:
    path = _intel_dir() / name
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    values = data.get("asns", data) if isinstance(data, dict) else data
    out: set[int] = set()
    for item in values:
        try:
            out.add(int(str(item).lstrip("ASas")))
        except ValueError:
            continue
    return out


def classify_infra(ip: str | None, asn: int | None, aso: str) -> str:
    if not ip:
        return "unknown"
    if ip in _tor_ips():
        return "tor_exit"
    org = (aso or "").lower()
    if asn in _vpn_asns() or any(mark in org for mark in VPN_ORG_MARKS):
        return "vpn"
    if asn in _cloud_asns() or any(mark in org for mark in CLOUD_ORG_MARKS):
        return "cloud_hosting"
    if any(mark in org for mark in HOSTING_ORG_MARKS):
        return "hosting"
    return "unclassified"


def cached_whois(domain: str) -> dict | None:
    if not domain:
        return None
    cache = whois_cache()
    rec = cache.get(domain.lower())
    return rec if isinstance(rec, dict) else None
