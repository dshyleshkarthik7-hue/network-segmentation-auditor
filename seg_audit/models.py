"""Core data models for zones, rules, and profiles."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Classification(str, Enum):
    """Security classification of a zone. Used for sensitive-ingress and blast-radius analysis."""

    INTERNET = "internet"
    PUBLIC = "public"          # DMZ-like
    APPLICATION = "application"
    SENSITIVE = "sensitive"    # data, databases, restricted
    MANAGEMENT = "management"
    INTERNAL = "internal"
    OT = "ot"                  # operational technology / ICS
    OTHER = "other"


SENSITIVE_CLASSIFICATIONS = frozenset(
    {
        Classification.SENSITIVE,
        Classification.MANAGEMENT,
        Classification.OT,
    }
)


class PolicySemantics(str, Enum):
    """How overlapping / ordered rules are evaluated."""

    FIRST_MATCH = "first-match"
    # Future: LAST_MATCH, DENY_OVERRIDES, ALLOW_UNION


@dataclass(frozen=True)
class Zone:
    """A named network zone with CIDR and security classification."""

    name: str
    cidr: str
    classification: Classification = Classification.OTHER
    description: str = ""

    def is_sensitive(self) -> bool:
        return self.classification in SENSITIVE_CLASSIFICATIONS

    def is_internet(self) -> bool:
        return self.classification == Classification.INTERNET


@dataclass(frozen=True)
class Rule:
    """A single zone-to-zone traffic rule.

    port may be:
      - an int (exact port)
      - 0 or the string "any" / "*" meaning any port
      - a string range "80-443" (inclusive)
    """

    source: str
    destination: str
    protocol: str  # "tcp", "udp", "icmp", "any", ...
    port: int | str  # 0 / "any" / int / "low-high"
    action: str  # "ALLOW" or "DENY"
    description: str = ""
    # Optional priority for future semantics; lower number = higher priority
    priority: int = 100

    def matches(self, source: str, destination: str, protocol: str, port: int) -> bool:
        if self.source != source or self.destination != destination:
            return False
        if self.protocol.lower() not in ("any", protocol.lower()):
            return False
        return self._port_matches(port)

    def _port_matches(self, port: int) -> bool:
        if self.port in (0, "any", "*"):
            return True
        if isinstance(self.port, int):
            return self.port == port
        if isinstance(self.port, str) and "-" in self.port:
            try:
                low, high = self.port.split("-", 1)
                return int(low) <= port <= int(high)
            except ValueError:
                return False
        return False

    def is_allow(self) -> bool:
        return self.action.upper() == "ALLOW"

    def is_any_port(self) -> bool:
        return self.port in (0, "any", "*") or (
            isinstance(self.port, str) and self.port.lower() in ("any", "*")
        )

    def is_any_protocol(self) -> bool:
        return self.protocol.lower() == "any"


@dataclass
class Profile:
    """Fully loaded and validated segmentation profile."""

    name: str
    description: str
    zones: dict[str, Zone]
    rules: list[Rule]
    sample_ips: dict[str, str] = field(default_factory=dict)
    policy_semantics: PolicySemantics = PolicySemantics.FIRST_MATCH

    @property
    def zone_names(self) -> list[str]:
        return list(self.zones.keys())

    def get_zone(self, name: str) -> Zone | None:
        return self.zones.get(name)
