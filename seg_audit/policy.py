"""Traffic-rule evaluation helpers."""

from __future__ import annotations

from .models import PolicySemantics, Rule


def first_match(
    source: str,
    destination: str,
    protocol: str,
    port: int,
    rules: list[Rule],
) -> Rule | None:
    """Return the first matching rule (order matters) or None."""
    for rule in rules:
        if rule.matches(source, destination, protocol, port):
            return rule
    return None


def evaluate(
    source: str,
    destination: str,
    protocol: str,
    port: int,
    rules: list[Rule],
    semantics: PolicySemantics = PolicySemantics.FIRST_MATCH,
) -> dict:
    """
    Evaluate a flow against the rule set.

    Explicit match → use rule action.
    No match → DENY (default-deny posture).
    """
    if semantics != PolicySemantics.FIRST_MATCH:
        # Placeholder for future semantics
        pass

    match = first_match(source, destination, protocol, port, rules)
    if match:
        return {
            "source": source,
            "destination": destination,
            "protocol": protocol.lower(),
            "port": port,
            "action": match.action.upper(),
            "matched": True,
            "description": match.description or f"Matched rule: {match.action.upper()}",
        }
    return {
        "source": source,
        "destination": destination,
        "protocol": protocol.lower(),
        "port": port,
        "action": "DENY",
        "matched": False,
        "description": "No explicit allow rule; default deny applies.",
    }


def find_shadowed_rules(rules: list[Rule]) -> list[dict]:
    """
    Detect rules that can never fire because an earlier rule already matches
    the same source/destination (and is at least as broad on protocol/port).
    """
    findings: list[dict] = []
    for i, later in enumerate(rules):
        for j, earlier in enumerate(rules[:i]):
            if earlier.source != later.source or earlier.destination != later.destination:
                continue
            # Earlier rule is broader or equal on protocol
            proto_covers = (
                earlier.protocol.lower() == "any"
                or earlier.protocol.lower() == later.protocol.lower()
            )
            # Earlier rule is broader or equal on port
            port_covers = earlier.is_any_port() or (
                isinstance(earlier.port, int)
                and isinstance(later.port, int)
                and earlier.port == later.port
            )
            if proto_covers and port_covers and earlier.action.upper() == later.action.upper():
                findings.append(
                    {
                        "severity": "LOW",
                        "type": "SHADOWED_RULE",
                        "rule": i + 1,
                        "shadowed_by": j + 1,
                        "message": (
                            f"Rule #{i + 1} ({later.source} → {later.destination}) "
                            f"is shadowed by earlier rule #{j + 1} with the same action."
                        ),
                    }
                )
                break
    return findings
