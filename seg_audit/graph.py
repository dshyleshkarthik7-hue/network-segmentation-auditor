"""Reachability graph and transitive path analysis.

This is the core improvement in v2.0: we model ALLOW rules as directed edges
and compute multi-hop reachability so the auditor can answer real questions
about blast radius and indirect exposure.
"""

from __future__ import annotations

from collections import defaultdict, deque

from .models import SENSITIVE_CLASSIFICATIONS, Profile, Rule


def build_allow_graph(profile: Profile) -> dict[str, list[tuple[str, Rule]]]:
    """
    Build adjacency list of ALLOW edges.

    Returns: {source_zone: [(dest_zone, rule), ...]}
    Only ALLOW rules become edges. DENY rules are ignored for reachability
    (they only matter for first-match evaluation of concrete flows).
    """
    graph: dict[str, list[tuple[str, Rule]]] = defaultdict(list)
    for rule in profile.rules:
        if rule.is_allow():
            graph[rule.source].append((rule.destination, rule))
    return dict(graph)


def find_paths(
    graph: dict[str, list[tuple[str, Rule]]],
    start: str,
    goal: str,
    max_depth: int = 8,
) -> list[list[str]]:
    """
    Find all simple paths from start to goal up to max_depth.
    Returns list of zone-name paths (including start and goal).
    """
    if start not in graph and start != goal:
        return []
    paths: list[list[str]] = []
    queue: deque[tuple[str, list[str]]] = deque([(start, [start])])

    while queue:
        node, path = queue.popleft()
        if len(path) > max_depth:
            continue
        if node == goal and len(path) > 1:
            paths.append(path)
            continue
        for neighbor, _ in graph.get(node, []):
            if neighbor not in path:  # simple paths only
                queue.append((neighbor, path + [neighbor]))
    return paths


def reachable_from(
    graph: dict[str, list[tuple[str, Rule]]],
    start: str,
    max_depth: int = 8,
) -> set[str]:
    """Return the set of zones reachable from start (excluding start itself)."""
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for neighbor, _ in graph.get(node, []):
            if neighbor not in visited and neighbor != start:
                visited.add(neighbor)
                queue.append((neighbor, depth + 1))
    return visited


def compute_reachability(profile: Profile) -> dict:
    """
    Compute full reachability summary for the profile.

    Returns a structured dict used by the audit engine and reports.
    """
    graph = build_allow_graph(profile)
    zones = profile.zone_names

    # Direct edges only
    direct: dict[str, list[str]] = {
        z: [dst for dst, _ in graph.get(z, [])] for z in zones
    }

    # Transitive reachability from every zone
    transitive: dict[str, list[str]] = {}
    for z in zones:
        reachable = sorted(reachable_from(graph, z))
        transitive[z] = reachable

    # Paths from internet-like zones to sensitive zones
    internet_zones = [
        name for name, zone in profile.zones.items() if zone.is_internet()
    ]
    sensitive_zones = [
        name
        for name, zone in profile.zones.items()
        if zone.classification in SENSITIVE_CLASSIFICATIONS
    ]

    sensitive_paths: list[dict] = []
    for src in internet_zones:
        for dst in sensitive_zones:
            paths = find_paths(graph, src, dst)
            for path in paths:
                sensitive_paths.append(
                    {
                        "from": src,
                        "to": dst,
                        "path": path,
                        "hops": len(path) - 1,
                    }
                )

    # Blast radius: for each zone, how many other zones become reachable
    blast_radius: dict[str, dict] = {}
    for z in zones:
        reachable = transitive.get(z, [])
        sensitive_reached = [
            r for r in reachable if profile.zones[r].classification in SENSITIVE_CLASSIFICATIONS
        ]
        blast_radius[z] = {
            "reachable_count": len(reachable),
            "reachable_zones": reachable,
            "sensitive_reached": sensitive_reached,
        }

    return {
        "direct": direct,
        "transitive": transitive,
        "internet_to_sensitive_paths": sensitive_paths,
        "blast_radius": blast_radius,
        "graph_edge_count": sum(len(v) for v in graph.values()),
    }


def format_path(path: list[str]) -> str:
    """Pretty-print a path as ZoneA → ZoneB → ZoneC."""
    return " → ".join(path)
