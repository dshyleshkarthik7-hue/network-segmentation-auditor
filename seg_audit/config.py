"""Load and validate segmentation profiles from JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    Classification,
    PolicySemantics,
    Profile,
    Rule,
    Zone,
)


def _parse_port(value: Any, rule_idx: int) -> int | str:
    if isinstance(value, str) and value.lower() in ("any", "*"):
        return 0
    if isinstance(value, str) and "-" in value:
        parts = value.split("-", 1)
        try:
            low, high = int(parts[0]), int(parts[1])
            if not (0 <= low <= high <= 65535):
                raise ValueError
            return value  # keep as range string
        except ValueError as exc:
            raise ValueError(
                f"Rule #{rule_idx}: invalid port range {value!r} (expected low-high, 0–65535)"
            ) from exc
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Rule #{rule_idx}: port must be an integer, range 'low-high', or 'any'"
        ) from exc
    if not (0 <= port <= 65535):
        raise ValueError(f"Rule #{rule_idx}: port {port} out of range 0–65535")
    return port


def _parse_classification(raw: Any, zone_name: str) -> Classification:
    if raw is None:
        # Heuristic fallback for legacy profiles
        upper = zone_name.upper()
        if upper in ("INTERNET", "ANY", "WORLD", "PUBLIC_INTERNET"):
            return Classification.INTERNET
        if upper in ("DMZ", "PUBLIC", "EDGE", "WEB"):
            return Classification.PUBLIC
        if upper in ("DATA", "DB", "DATABASE", "SENSITIVE", "RESTRICTED", "FINANCE"):
            return Classification.SENSITIVE
        if upper in ("MANAGEMENT", "MGMT", "ADMIN", "JUMP"):
            return Classification.MANAGEMENT
        if upper in ("OT", "ICS", "SCADA"):
            return Classification.OT
        if upper in ("APPLICATION", "APP", "BACKEND", "INTERNAL"):
            return Classification.APPLICATION
        return Classification.OTHER
    try:
        return Classification(str(raw).lower())
    except ValueError as exc:
        raise ValueError(
            f"Zone {zone_name!r}: unknown classification {raw!r}. "
            f"Valid: {[c.value for c in Classification]}"
        ) from exc


def load_config(path: str) -> Profile:
    """
    Load a JSON segmentation profile.

    Supports both the v2 schema (zones object with classification) and the
    legacy v1 schema (flat "networks" map) for smooth migration.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Root of config must be a JSON object")

    # ---- Zones ----
    zones: dict[str, Zone] = {}

    if "zones" in data:
        raw_zones = data["zones"]
        if not isinstance(raw_zones, dict) or not raw_zones:
            raise ValueError("'zones' must be a non-empty object")
        for name, spec in raw_zones.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"Invalid zone name: {name!r}")
            if isinstance(spec, str):
                # shorthand: "ZONE": "10.0.1.0/24"
                cidr = spec
                classification = _parse_classification(None, name)
                description = ""
            elif isinstance(spec, dict):
                raw_cidr = spec.get("cidr")
                if not raw_cidr or not isinstance(raw_cidr, str):
                    raise ValueError(f"Zone {name!r} missing or invalid 'cidr'")
                cidr = raw_cidr.strip()
                classification = _parse_classification(spec.get("classification"), name)
                description = str(spec.get("description", ""))
            else:
                raise ValueError(f"Zone {name!r} must be a CIDR string or object")
            zones[name.strip()] = Zone(
                name=name.strip(),
                cidr=cidr,
                classification=classification,
                description=description,
            )
    elif "networks" in data:
        # Legacy v1 compatibility
        networks = data["networks"]
        if not isinstance(networks, dict) or not networks:
            raise ValueError("'networks' must be a non-empty object mapping zone → CIDR")
        for name, cidr in networks.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"Invalid zone name: {name!r}")
            zones[name.strip()] = Zone(
                name=name.strip(),
                cidr=str(cidr).strip(),
                classification=_parse_classification(None, name),
            )
    else:
        raise ValueError("Profile must contain either 'zones' (v2) or 'networks' (v1)")

    # ---- Rules ----
    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        raise ValueError("'rules' must be a list")

    required = {"source", "destination", "protocol", "port", "action"}
    rules: list[Rule] = []
    for idx, item in enumerate(rules_raw, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Rule #{idx} must be an object")
        missing = required - item.keys()
        if missing:
            raise ValueError(f"Rule #{idx} missing keys: {sorted(missing)}")

        port = _parse_port(item["port"], idx)
        action = str(item["action"]).upper()
        if action not in ("ALLOW", "DENY"):
            raise ValueError(f"Rule #{idx}: action must be ALLOW or DENY, got {item['action']!r}")

        protocol = str(item["protocol"]).lower().strip()
        if not protocol:
            raise ValueError(f"Rule #{idx}: protocol must be non-empty")

        rules.append(
            Rule(
                source=str(item["source"]).strip(),
                destination=str(item["destination"]).strip(),
                protocol=protocol,
                port=port,
                action=action,
                description=str(item.get("description", "")),
                priority=int(item.get("priority", 100)),
            )
        )

    # ---- Sample IPs ----
    sample_ips = data.get("sample_ips", {})
    if not isinstance(sample_ips, dict):
        raise ValueError("'sample_ips' must be an object mapping name → IP")

    # ---- Semantics ----
    semantics_raw = data.get("policy_semantics", "first-match")
    try:
        semantics = PolicySemantics(str(semantics_raw).lower())
    except ValueError as exc:
        raise ValueError(
            f"Unknown policy_semantics {semantics_raw!r}. "
            f"Supported: {[s.value for s in PolicySemantics]}"
        ) from exc

    return Profile(
        name=str(data.get("name", "unnamed")),
        description=str(data.get("description", "")),
        zones=zones,
        rules=rules,
        sample_ips={str(k): str(v) for k, v in sample_ips.items()},
        policy_semantics=semantics,
    )
