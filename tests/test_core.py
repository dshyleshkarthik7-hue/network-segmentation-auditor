"""Core unit tests for Network Segmentation Auditor v2."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from seg_audit.audit import audit
from seg_audit.cidr import classify_ip, find_overlaps, parse_network
from seg_audit.config import load_config
from seg_audit.graph import compute_reachability
from seg_audit.models import Classification, Rule, Zone
from seg_audit.policy import evaluate, find_shadowed_rules

# ---------------------------------------------------------------------------
# CIDR helpers
# ---------------------------------------------------------------------------


def test_parse_network_normalises() -> None:
    net = parse_network("10.0.1.10/24")
    assert str(net) == "10.0.1.0/24"


def test_parse_network_invalid() -> None:
    with pytest.raises(ValueError):
        parse_network("not-a-cidr")


def test_classify_ip_basic() -> None:
    zones = {
        "DMZ": Zone("DMZ", "10.0.1.0/24", Classification.PUBLIC),
        "APP": Zone("APP", "10.0.2.0/24", Classification.APPLICATION),
    }
    assert classify_ip("10.0.1.5", zones) == "DMZ"
    assert classify_ip("10.0.2.99", zones) == "APP"
    assert classify_ip("192.0.2.1", zones) == "UNKNOWN"


def test_classify_ip_most_specific_wins() -> None:
    zones = {
        "BROAD": Zone("BROAD", "10.0.0.0/16", Classification.PUBLIC),
        "NARROW": Zone("NARROW", "10.0.2.0/24", Classification.APPLICATION),
    }
    assert classify_ip("10.0.2.50", zones) == "NARROW"
    assert classify_ip("10.0.1.50", zones) == "BROAD"


def test_find_overlaps() -> None:
    zones = {
        "OUTER": Zone("OUTER", "10.0.0.0/16", Classification.PUBLIC),
        "INNER": Zone("INNER", "10.0.2.0/24", Classification.APPLICATION),
        "OTHER": Zone("OTHER", "192.168.0.0/24", Classification.INTERNAL),
    }
    findings = find_overlaps(zones)
    assert len(findings) == 1
    assert findings[0]["type"] == "CIDR_OVERLAP"


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------


def test_default_deny() -> None:
    result = evaluate("DMZ", "DATA", "tcp", 5432, [])
    assert result["action"] == "DENY"
    assert result["matched"] is False


def test_explicit_allow() -> None:
    rules = [
        Rule(
            source="DMZ",
            destination="DATA",
            protocol="tcp",
            port=5432,
            action="ALLOW",
            description="db",
        )
    ]
    result = evaluate("DMZ", "DATA", "tcp", 5432, rules)
    assert result["action"] == "ALLOW"
    assert result["matched"] is True


def test_any_port_and_protocol() -> None:
    rules = [
        Rule(
            source="MGMT",
            destination="APP",
            protocol="any",
            port=0,
            action="ALLOW",
            description="full access",
        )
    ]
    result = evaluate("MGMT", "APP", "udp", 161, rules)
    assert result["action"] == "ALLOW"


def test_port_range() -> None:
    rules = [
        Rule(
            source="INTERNET",
            destination="DMZ",
            protocol="tcp",
            port="80-443",
            action="ALLOW",
        )
    ]
    assert evaluate("INTERNET", "DMZ", "tcp", 80, rules)["action"] == "ALLOW"
    assert evaluate("INTERNET", "DMZ", "tcp", 443, rules)["action"] == "ALLOW"
    assert evaluate("INTERNET", "DMZ", "tcp", 22, rules)["action"] == "DENY"


def test_shadowed_rule() -> None:
    rules = [
        Rule("A", "B", "any", 0, "ALLOW"),
        Rule("A", "B", "tcp", 80, "ALLOW"),  # shadowed
    ]
    findings = find_shadowed_rules(rules)
    assert len(findings) == 1
    assert findings[0]["type"] == "SHADOWED_RULE"


# ---------------------------------------------------------------------------
# Graph / reachability
# ---------------------------------------------------------------------------


def test_transitive_path() -> None:
    from seg_audit.models import Profile

    profile = Profile(
        name="t",
        description="",
        zones={
            "INTERNET": Zone("INTERNET", "0.0.0.0/0", Classification.INTERNET),
            "DMZ": Zone("DMZ", "10.0.1.0/24", Classification.PUBLIC),
            "APP": Zone("APP", "10.0.2.0/24", Classification.APPLICATION),
            "DATA": Zone("DATA", "10.0.3.0/24", Classification.SENSITIVE),
        },
        rules=[
            Rule("INTERNET", "DMZ", "tcp", 443, "ALLOW"),
            Rule("DMZ", "APP", "tcp", 8443, "ALLOW"),
            Rule("APP", "DATA", "tcp", 5432, "ALLOW"),
        ],
    )
    reach = compute_reachability(profile)
    paths = reach["internet_to_sensitive_paths"]
    assert len(paths) >= 1
    assert any(p["hops"] == 3 for p in paths)
    assert "DATA" in reach["transitive"]["INTERNET"]


def test_unexpected_transitive_path() -> None:
    from seg_audit.models import Profile

    profile = Profile(
        name="t",
        description="",
        zones={
            "INTERNET": Zone("INTERNET", "0.0.0.0/0", Classification.INTERNET),
            "APP": Zone("APP", "10.0.2.0/24", Classification.APPLICATION),
            "DATA": Zone("DATA", "10.0.3.0/24", Classification.SENSITIVE),
        },
        rules=[
            Rule("INTERNET", "APP", "tcp", 443, "ALLOW"),
            Rule("APP", "DATA", "tcp", 5432, "ALLOW"),
        ],
    )
    reach = compute_reachability(profile)
    assert any(p["hops"] == 2 for p in reach["internet_to_sensitive_paths"])



def test_no_transitive_when_broken() -> None:
    from seg_audit.models import Profile

    profile = Profile(
        name="t",
        description="",
        zones={
            "INTERNET": Zone("INTERNET", "0.0.0.0/0", Classification.INTERNET),
            "DMZ": Zone("DMZ", "10.0.1.0/24", Classification.PUBLIC),
            "DATA": Zone("DATA", "10.0.3.0/24", Classification.SENSITIVE),
        },
        rules=[
            Rule("INTERNET", "DMZ", "tcp", 443, "ALLOW"),
            # no path onward to DATA
        ],
    )
    reach = compute_reachability(profile)
    assert reach["internet_to_sensitive_paths"] == []
    assert "DATA" not in reach["transitive"]["INTERNET"]


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def test_load_config_v2(tmp_path: Path) -> None:
    data = {
        "name": "t",
        "zones": {
            "A": {"cidr": "10.0.0.0/24", "classification": "public"},
            "B": {"cidr": "10.0.1.0/24", "classification": "sensitive"},
        },
        "rules": [
            {
                "source": "A",
                "destination": "B",
                "protocol": "tcp",
                "port": 80,
                "action": "ALLOW",
            }
        ],
        "sample_ips": {"h": "10.0.0.5"},
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    cfg = load_config(str(p))
    assert cfg.name == "t"
    assert cfg.zones["B"].classification == Classification.SENSITIVE
    assert len(cfg.rules) == 1


def test_load_config_legacy_v1(tmp_path: Path) -> None:
    data = {
        "name": "legacy",
        "networks": {"INTERNET": "0.0.0.0/0", "DATA": "10.0.3.0/24"},
        "rules": [],
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    cfg = load_config(str(p))
    assert cfg.zones["DATA"].classification == Classification.SENSITIVE
    assert cfg.zones["INTERNET"].classification == Classification.INTERNET


def test_load_config_port_any(tmp_path: Path) -> None:
    data = {
        "name": "t",
        "zones": {
            "A": {"cidr": "10.0.0.0/24"},
            "B": {"cidr": "10.0.1.0/24"},
        },
        "rules": [
            {
                "source": "A",
                "destination": "B",
                "protocol": "tcp",
                "port": "any",
                "action": "ALLOW",
            }
        ],
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    cfg = load_config(str(p))
    assert cfg.rules[0].port == 0


# ---------------------------------------------------------------------------
# Full audit
# ---------------------------------------------------------------------------


def test_audit_transitive_high_unexpected(tmp_path: Path) -> None:
    """Internet → application → sensitive (no public entry) is HIGH."""
    data = {
        "name": "transitive-bad",
        "zones": {
            "INTERNET": {"cidr": "0.0.0.0/0", "classification": "internet"},
            "APP": {"cidr": "10.0.2.0/24", "classification": "application"},
            "DATA": {"cidr": "10.0.3.0/24", "classification": "sensitive"},
        },
        "rules": [
            {"source": "INTERNET", "destination": "APP", "protocol": "tcp", "port": 443, "action": "ALLOW"},
            {"source": "APP", "destination": "DATA", "protocol": "tcp", "port": 5432, "action": "ALLOW"},
        ],
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    report = audit(load_config(str(p)))
    high = [f for f in report["findings"] if f["severity"] == "HIGH"]
    assert any(f["type"] == "TRANSITIVE_SENSITIVE_REACHABILITY" for f in high)
    assert report["summary"]["HIGH"] >= 1


def test_audit_transitive_expected_tiering_is_info(tmp_path: Path) -> None:
    """Classic Internet → public → app → sensitive is intentional, not HIGH."""
    data = {
        "name": "transitive-ok",
        "zones": {
            "INTERNET": {"cidr": "0.0.0.0/0", "classification": "internet"},
            "DMZ": {"cidr": "10.0.1.0/24", "classification": "public"},
            "APP": {"cidr": "10.0.2.0/24", "classification": "application"},
            "DATA": {"cidr": "10.0.3.0/24", "classification": "sensitive"},
        },
        "rules": [
            {"source": "INTERNET", "destination": "DMZ", "protocol": "tcp", "port": 443, "action": "ALLOW"},
            {"source": "DMZ", "destination": "APP", "protocol": "tcp", "port": 8443, "action": "ALLOW"},
            {"source": "APP", "destination": "DATA", "protocol": "tcp", "port": 5432, "action": "ALLOW"},
        ],
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    report = audit(load_config(str(p)))
    assert report["summary"]["HIGH"] == 0
    info = [f for f in report["findings"] if f["type"] == "TRANSITIVE_SENSITIVE_REACHABILITY"]
    assert len(info) >= 1
    assert info[0]["severity"] == "INFO"


def test_audit_direct_sensitive(tmp_path: Path) -> None:
    data = {
        "name": "unsafe",
        "zones": {
            "INTERNET": {"cidr": "0.0.0.0/0", "classification": "internet"},
            "DATA": {"cidr": "10.0.3.0/24", "classification": "sensitive"},
        },
        "rules": [
            {
                "source": "INTERNET",
                "destination": "DATA",
                "protocol": "tcp",
                "port": 5432,
                "action": "ALLOW",
            }
        ],
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    report = audit(load_config(str(p)))
    assert report["summary"]["HIGH"] >= 1
    types = {f["type"] for f in report["findings"]}
    assert "SENSITIVE_INGRESS" in types


def test_audit_safe_no_high(tmp_path: Path) -> None:
    data = {
        "name": "safe",
        "zones": {
            "INTERNET": {"cidr": "0.0.0.0/0", "classification": "internet"},
            "DMZ": {"cidr": "10.0.1.0/24", "classification": "public"},
            "DATA": {"cidr": "10.0.3.0/24", "classification": "sensitive"},
        },
        "rules": [
            {"source": "INTERNET", "destination": "DMZ", "protocol": "tcp", "port": 443, "action": "ALLOW"},
            # no path to DATA
        ],
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    report = audit(load_config(str(p)))
    assert report["summary"]["HIGH"] == 0
