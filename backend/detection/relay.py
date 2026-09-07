"""Parse Received hops and pick the earliest *reliable* public relay IP."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

IP_IN_BRACKETS = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
IP_AFTER_FROM = re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE)
IP_ANY = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Hops mentioning these are treated as trusted MTAs; earlier hops may be client-forged.
TRUSTED_MTA_MARKS = (
    "google.com",
    "googlemail.com",
    "mail-sor-",
    "outlook.com",
    "protection.outlook.com",
    "yahoodns.net",
    "yahoo.com",
    "ppmessage",
    "guardian.local",
    "mail-gateway",
)


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
    # RFC 6598 carrier-grade NAT
    if a == 100 and 64 <= b <= 127:
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


def _looks_trusted_mta(line: str) -> bool:
    low = (line or "").lower()
    return any(mark in low for mark in TRUSTED_MTA_MARKS)


@dataclass
class RelayHop:
    received: str
    ips: list[str] = field(default_factory=list)
    public_ips: list[str] = field(default_factory=list)
    trusted_mta: bool = False


@dataclass
class RelayPath:
    hops: list[RelayHop]
    earliest_public_ip: str | None
    note: str
    reliable: bool = False
    discarded_untrusted_prefix: int = 0


def parse_relay_path(raw_headers: str) -> RelayPath:
    """Received headers are newest-first.

    Prefer the earliest public IP that appears on or after a trusted MTA hop.
    Hops before the first trusted MTA are treated as potentially forged.
    """
    hops: list[RelayHop] = []
    for value in header_values(raw_headers, "received"):
        ips = _ips_in_received(value)
        pub = [ip for ip in ips if is_public_ipv4(ip)]
        hops.append(
            RelayHop(
                received=value,
                ips=ips,
                public_ips=pub,
                trusted_mta=_looks_trusted_mta(value),
            )
        )

    if not hops:
        return RelayPath(hops=[], earliest_public_ip=None, note="No Received headers; origin IP cannot be inferred from this file.")

    # Newest → oldest index. Find first trusted MTA from the top (newest).
    trusted_idx = next((i for i, h in enumerate(hops) if h.trusted_mta), None)
    if trusted_idx is None:
        # No known trusted MTA: use last public IP but mark low reliability.
        public = [ip for h in hops for ip in h.public_ips]
        ip = public[-1] if public else None
        return RelayPath(
            hops=hops,
            earliest_public_ip=ip,
            note="No trusted MTA marker found; earliest public IP is best-effort and may include forged hops.",
            reliable=False,
            discarded_untrusted_prefix=0,
        )

    # Trusted segment: from trusted_idx to end (older hops after first trusted receive).
    # Earliest reliable = last public IP in that trusted segment.
    trusted_segment = hops[trusted_idx:]
    public = [ip for h in trusted_segment for ip in h.public_ips]
    ip = public[-1] if public else None
    discarded = trusted_idx  # hops newer than trusted? Actually hops before trusted_idx are newer.
    # Untrusted *older* forged client hops would be AFTER the last trusted hop in the list.
    # Classic pattern: [newest Gmail, ..., oldest forged]. Trusted is near top; forged is at bottom.
    # So earliest reliable among trusted segment is correct; hops after last trusted MTA in the list
    # that claim exotic IPs are less trusted.
    last_trusted = max(i for i, h in enumerate(hops) if h.trusted_mta)
    forged_tail = hops[last_trusted + 1 :]
    discarded_tail = len(forged_tail)
    if forged_tail:
        # Prefer IP from the last trusted hop itself when present.
        trusted_hop = hops[last_trusted]
        if trusted_hop.public_ips:
            ip = trusted_hop.public_ips[-1]
        note = (
            "Earliest reliable hop is the last trusted MTA public IP; "
            f"{discarded_tail} older Received line(s) treated as unverified/possibly forged."
        )
        return RelayPath(
            hops=hops,
            earliest_public_ip=ip,
            note=note,
            reliable=True,
            discarded_untrusted_prefix=discarded_tail,
        )

    return RelayPath(
        hops=hops,
        earliest_public_ip=ip,
        note="Earliest public IP on/after a trusted MTA (probable originating infrastructure).",
        reliable=True,
        discarded_untrusted_prefix=0,
    )


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
