"""Core audit engine — produce findings from a loaded profile.

v2.0 adds true multi-hop reachability analysis via the graph module.
"""

from __future__ import annotations

from typing import Any

from .cidr import classify_ip, find_overlaps, parse_network
from .graph import compute_reachability, format_path
from .models import SENSITIVE_CLASSIFICATIONS, Profile
from .policy import find_shadowed_rules

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def audit(profile: Profile) -> dict[str, Any]:
    """
    Analyse a segmentation profile and return a structured report.

    Checks performed:
    - Invalid CIDRs
    - Overlapping / nested CIDRs
    - Rules referencing undefined zones
    - Direct Internet → sensitive-zone ALLOW
    - **Transitive** Internet → sensitive paths (multi-hop)
    - Overly broad allows
    - Shadowed rules
    - Missing explicit zone-to-zone rules (default-deny reminder)
    - Sample IP classification (most-specific match)
    - Blast-radius summary
    """
    findings: list[dict] = []
    zones = profile.zones
    zone_set = set(zones.keys())
    rules = profile.rules

    # 1. CIDR validity
    for name, zone in zones.items():
        try:
            parse_network(zone.cidr)
        except ValueError as exc:
            findings.append(
                {
                    "severity": "HIGH",
                    "type": "INVALID_CIDR",
                    "zone": name,
                    "message": f"Zone {name!r} has invalid CIDR {zone.cidr!r}: {exc}",
                }
            )

    # 2. Overlaps (only if CIDRs parsed cleanly)
    if not any(f["type"] == "INVALID_CIDR" for f in findings):
        findings.extend(find_overlaps(zones))

    # 3. Rule hygiene + direct sensitive ingress + overly broad
    for idx, rule in enumerate(rules, 1):
        if rule.source not in zone_set or rule.destination not in zone_set:
            findings.append(
                {
                    "severity": "HIGH",
                    "type": "UNKNOWN_ZONE",
                    "rule": idx,
                    "message": (
                        f"Rule #{idx} references undefined zone: "
                        f"{rule.source} → {rule.destination}."
                    ),
                }
            )
            continue

        src_zone = zones[rule.source]
        dst_zone = zones[rule.destination]

        # Direct sensitive ingress
        if (
            rule.is_allow()
            and src_zone.is_internet()
            and dst_zone.classification in SENSITIVE_CLASSIFICATIONS
        ):
            findings.append(
                {
                    "severity": "HIGH",
                    "type": "SENSITIVE_INGRESS",
                    "rule": idx,
                    "message": (
                        f"Rule #{idx} allows Internet ingress to sensitive zone "
                        f"{rule.destination} ({dst_zone.classification.value}) "
                        f"({rule.protocol.upper()}/{rule.port or 'any'}). "
                        "This expands blast radius dramatically."
                    ),
                }
            )

        # Overly broad allows from Internet
        if (
            rule.is_allow()
            and src_zone.is_internet()
            and rule.is_any_port()
            and rule.is_any_protocol()
        ):
            findings.append(
                {
                    "severity": "MEDIUM",
                    "type": "OVERLY_BROAD_ALLOW",
                    "rule": idx,
                    "message": (
                        f"Rule #{idx} allows Internet → {rule.destination} "
                        "for any protocol/port. Prefer least-privilege rules."
                    ),
                }
            )

    # 4. Shadowed rules
    findings.extend(find_shadowed_rules(rules))

    # 5. Reachability analysis (the core v2 improvement)
    reach = compute_reachability(profile)

    for path_info in reach["internet_to_sensitive_paths"]:
        hops = path_info["hops"]
        path = path_info["path"]
        path_str = format_path(path)
        if hops == 1:
            # Already covered by SENSITIVE_INGRESS
            continue

        # Expected classic tiering: Internet → public → … → sensitive
        # is intentional design and should not be a HIGH finding.
        # Flag HIGH only when the path skips a public/DMZ entry point
        # (e.g. Internet → application → sensitive, or via management).
        first_hop = path[1] if len(path) > 1 else None
        first_cls = (
            zones[first_hop].classification.value if first_hop and first_hop in zones else ""
        )
        expected_entry = first_cls == "public"

        if expected_entry:
            # Still surface as INFO so designers see the path exists
            findings.append(
                {
                    "severity": "INFO",
                    "type": "TRANSITIVE_SENSITIVE_REACHABILITY",
                    "from": path_info["from"],
                    "to": path_info["to"],
                    "path": path,
                    "message": (
                        f"Controlled multi-hop path to sensitive zone "
                        f"{path_info['to']}: {path_str} ({hops} hops). "
                        "Entry is via a public zone — typical tiered design."
                    ),
                }
            )
        else:
            findings.append(
                {
                    "severity": "HIGH",
                    "type": "TRANSITIVE_SENSITIVE_REACHABILITY",
                    "from": path_info["from"],
                    "to": path_info["to"],
                    "path": path,
                    "message": (
                        f"Internet-originated traffic can reach sensitive zone "
                        f"{path_info['to']} via unexpected {hops}-hop path: "
                        f"{path_str} (first hop is not a public/DMZ zone). "
                        "This expands blast radius beyond intended tiering."
                    ),
                }
            )

    # 6. Missing explicit rules (INFO — reinforces default-deny thinking)
    # Limit noise: only report if the pair has no rule at all
    for src in zones:
        for dst in zones:
            if src == dst:
                continue
            if not any(r.source == src and r.destination == dst for r in rules):
                findings.append(
                    {
                        "severity": "INFO",
                        "type": "NO_EXPLICIT_RULE",
                        "source": src,
                        "destination": dst,
                        "message": (
                            f"No explicit rule for {src} → {dst}; "
                            "default-deny interpretation applies."
                        ),
                    }
                )

    # 7. Sample IP classification
    classifications = {
        name: classify_ip(ip, zones) for name, ip in profile.sample_ips.items()
    }
    for name, zone_name in classifications.items():
        if zone_name == "UNKNOWN":
            findings.append(
                {
                    "severity": "LOW",
                    "type": "UNCLASSIFIED_IP",
                    "sample": name,
                    "message": (
                        f"Sample IP {name!r} ({profile.sample_ips[name]}) "
                        "does not fall into any defined zone."
                    ),
                }
            )

    # Sort & summarise
    findings.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 99), x["type"]))
    summary = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    return {
        "version": "2.0.0",
        "profile": profile.name,
        "description": profile.description,
        "summary": summary,
        "zones": {
            name: {
                "cidr": z.cidr,
                "classification": z.classification.value,
                "description": z.description,
            }
            for name, z in zones.items()
        },
        "sample_classifications": classifications,
        "reachability": reach,
        "findings": findings,
        "rule_count": len(rules),
        "zone_count": len(zones),
        "policy_semantics": profile.policy_semantics.value,
    }
