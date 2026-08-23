"""Human-readable and JSON report generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .graph import format_path


def save_json(report: dict[str, Any], path: str) -> None:
    """Write the full report as pretty-printed JSON."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def print_report(report: dict[str, Any]) -> None:
    """Print a concise human-readable summary to stdout."""
    print(f"Profile : {report['profile']}")
    if report.get("description"):
        print(f"Desc    : {report['description']}")
    print(f"Zones   : {report.get('zone_count', '?')}")
    print(f"Rules   : {report.get('rule_count', '?')}")
    print(f"Semantics: {report.get('policy_semantics', 'first-match')}")
    print()
    print("Summary")
    print("-------")
    for key in ("HIGH", "MEDIUM", "LOW", "INFO"):
        value = report["summary"].get(key, 0)
        print(f"  {key:<8} {value}")

    # Reachability highlights
    reach = report.get("reachability") or {}
    paths = reach.get("internet_to_sensitive_paths") or []
    if paths:
        print()
        print("Internet → Sensitive paths (transitive)")
        print("---------------------------------------")
        for p in paths:
            print(f"  {format_path(p['path'])}  ({p['hops']} hop{'s' if p['hops'] != 1 else ''})")

    classifications = report.get("sample_classifications") or {}
    if classifications:
        print()
        print("Sample IP classification")
        print("------------------------")
        for name, zone in sorted(classifications.items()):
            print(f"  {name:<16} → {zone}")

    print()
    print("Findings")
    print("--------")
    findings = report.get("findings") or []
    if not findings:
        print("  (none)")
        return

    current_sev = None
    for f in findings:
        sev = f["severity"]
        if sev != current_sev:
            current_sev = sev
            print(f"\n  [{sev}]")
        print(f"    • {f['type']}: {f['message']}")


def mermaid_diagram(report: dict[str, Any]) -> str:
    """
    Produce a Mermaid flowchart of zones and *actual* ALLOW edges.
    """
    zones = report.get("zones") or {}
    reach = report.get("reachability") or {}
    direct = reach.get("direct") or {}

    lines = ["```mermaid", "flowchart TD"]
    for name, info in zones.items():
        safe = name.replace("-", "_").replace(" ", "_")
        cls = info.get("classification", "other")
        cidr = info.get("cidr", "")
        lines.append(f'    {safe}["{name}<br/>{cidr}<br/><i>{cls}</i>"]')

    # Emit real ALLOW edges
    seen: set[tuple[str, str]] = set()
    for src, dests in direct.items():
        for dst in dests:
            key = (src, dst)
            if key in seen:
                continue
            seen.add(key)
            s = src.replace("-", "_").replace(" ", "_")
            d = dst.replace("-", "_").replace(" ", "_")
            lines.append(f"    {s} --> {d}")

    lines.append("```")
    return "\n".join(lines)
