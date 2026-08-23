"""CIDR parsing, zone classification of IPs, and overlap detection."""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Union

from .models import Zone

Network = Union[IPv4Network, IPv6Network]

_CATCHALL_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def parse_network(value: str) -> Network:
    """Parse a CIDR string. Raises ValueError on invalid input."""
    return ip_network(value, strict=False)


def classify_ip(ip: str, zones: dict[str, Zone]) -> str:
    """
    Return the zone name that contains *ip*.

    When multiple zones match (nested/overlapping CIDRs), the most specific
    (longest prefix) network wins. Returns ``UNKNOWN`` if no zone contains the IP.
    """
    try:
        address = ip_address(ip)
    except ValueError:
        return "UNKNOWN"

    matches: list[tuple[int, str]] = []
    for name, zone in zones.items():
        try:
            net = parse_network(zone.cidr)
            if address in net:
                matches.append((net.prefixlen, name))
        except ValueError:
            continue
    if not matches:
        return "UNKNOWN"
    matches.sort(key=lambda x: x[0], reverse=True)
    return matches[0][1]


def find_overlaps(zones: dict[str, Zone]) -> list[dict]:
    """
    Detect overlapping or nested CIDRs between zones.

    Intentional internet catch-alls (classification=internet or 0.0.0.0/0 / ::/0)
    are excluded from overlap reporting.
    """
    findings: list[dict] = []
    items = [
        (name, zone)
        for name, zone in zones.items()
        if not zone.is_internet() and zone.cidr not in _CATCHALL_CIDRS
    ]
    for i, (name_a, zone_a) in enumerate(items):
        try:
            net_a = parse_network(zone_a.cidr)
        except ValueError:
            continue
        for name_b, zone_b in items[i + 1 :]:
            try:
                net_b = parse_network(zone_b.cidr)
            except ValueError:
                continue
            if net_a.overlaps(net_b):
                if net_a.prefixlen > net_b.prefixlen and net_a.network_address in net_b:
                    relation = (
                        f"{name_a} ({zone_a.cidr}) is nested inside "
                        f"{name_b} ({zone_b.cidr})"
                    )
                elif net_b.prefixlen > net_a.prefixlen and net_b.network_address in net_a:
                    relation = (
                        f"{name_b} ({zone_b.cidr}) is nested inside "
                        f"{name_a} ({zone_a.cidr})"
                    )
                else:
                    relation = (
                        f"{name_a} ({zone_a.cidr}) overlaps "
                        f"{name_b} ({zone_b.cidr})"
                    )
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "type": "CIDR_OVERLAP",
                        "zones": [name_a, name_b],
                        "message": (
                            f"{relation}. Overlapping zones can produce "
                            "ambiguous classification and unexpected reachability."
                        ),
                    }
                )
    return findings
