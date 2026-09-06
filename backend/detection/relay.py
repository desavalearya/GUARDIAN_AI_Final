"""Parse Received hops and pick the earliest reliable public relay IP."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

IP_IN_BRACKETS = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
IP_AFTER_FROM = re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE)


def is_public_ipv4(ip: str) -> bool:
    try:
        parts = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        return False
    a, b = parts[0], parts[1]
    if a == 0 or a == 10 or a == 127:
        return False
    if a == 169 and b == 254:
        return False
    if a == 192 and b == 168:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a >= 224:
        return False
    return True


def _header_blocks(raw_headers: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    current_name = ""
    current_value: list[str] = []
    for line in (raw_headers or "").splitlines():
        if not line:
            continue
        if line[0] in " \t" and current_name:
            current_value.append(line.strip())
            continue
        if current_name:
            blocks.append((current_name, " ".join(current_value)))
        if ":" not in line:
            current_name = ""
            current_value = []
            continue
        name, value = line.split(":", 1)
        current_name = name.strip().lower()
        current_value = [value.strip()]
    if current_name:
        blocks.append((current_name, " ".join(current_value)))
    return blocks


def header_values(raw_headers: str, name: str) -> list[str]:
    key = name.lower()
    return [value for n, value in _header_blocks(raw_headers) if n == key]


def _ips_in_received(line: str) -> list[str]:
    found: list[str] = []
    for match in IP_IN_BRACKETS.findall(line or ""):
        found.append(match)
    if not found:
        found.extend(IP_AFTER_FROM.findall(line or ""))
    return found


@dataclass
class RelayHop:
    received: str
    ips: list[str] = field(default_factory=list)
    public_ips: list[str] = field(default_factory=list)


@dataclass
class RelayPath:
    hops: list[RelayHop]
    earliest_public_ip: str | None
    note: str


def parse_relay_path(raw_headers: str) -> RelayPath:
    """Received headers are newest-first. Last public IP is the earliest reliable hop."""
    hops: list[RelayHop] = []
    public: list[str] = []
    for value in header_values(raw_headers, "received"):
        ips = _ips_in_received(value)
        pub = [ip for ip in ips if is_public_ipv4(ip)]
        hops.append(RelayHop(received=value, ips=ips, public_ips=pub))
        public.extend(pub)
    ip = public[-1] if public else None
    if ip:
        note = "Earliest public IP in the Received chain (probable originating infrastructure)."
    elif hops:
        note = "Received hops present but no public IPv4 (internal or missing)."
    else:
        note = "No Received headers; origin IP cannot be inferred from this file."
    return RelayPath(hops=hops, earliest_public_ip=ip, note=note)


def header_anomalies(raw_headers: str, sender_address: str) -> list[str]:
    flags: list[str] = []
    sender_domain = sender_address.split("@")[-1].lower() if "@" in (sender_address or "") else ""

    from_vals = header_values(raw_headers, "from")
    return_paths = header_values(raw_headers, "return-path")
    reply_tos = header_values(raw_headers, "reply-to")

    def _addr_domain(raw: str) -> str:
        match = re.search(r"([\w.+-]+@[\w.-]+)", raw or "")
        if not match:
            return ""
        return match.group(1).split("@")[-1].lower()

    for rp in return_paths:
        domain = _addr_domain(rp)
        if sender_domain and domain and domain != sender_domain:
            flags.append(f"return-path-domain-mismatch:{domain}")
    for rt in reply_tos:
        domain = _addr_domain(rt)
        if sender_domain and domain and domain != sender_domain:
            flags.append(f"reply-to-domain-mismatch:{domain}")
    if from_vals and return_paths:
        from_dom = _addr_domain(from_vals[0])
        rp_dom = _addr_domain(return_paths[0])
        if from_dom and rp_dom and from_dom != rp_dom:
            flags.append("from-vs-return-path-mismatch")
    return flags
