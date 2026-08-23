# Design Notes (v2.0)

## Goals

1. Teach the difference between *subnetting*, *security policy*, and *reachability*.
2. Stay completely passive (no packets, no discovery, no firewall mutation).
3. Be installable and CI-friendly with zero runtime dependencies.
4. Produce findings that map cleanly to real-world design reviews.
5. Answer the questions a segmentation review actually asks:
   - Can Internet traffic (directly or transitively) reach sensitive zones?
   - What is the blast radius if zone X is compromised?
   - Which paths exist from A to B under the current ALLOW rules?

## Non-goals

- Live network scanning or validation against running devices.
- Full firewall rule-set modelling (NAT, stateful inspection, application-layer gateways).
- Cloud-provider security-group translation (can be added later as exporters).
- Perfect simulation of every vendor’s ACL evaluation order.

## Core concepts

### Zones

A zone is a named CIDR plus an explicit **classification**:

- `internet`
- `public` (DMZ-like)
- `application`
- `sensitive` (data, databases, restricted)
- `management`
- `internal`
- `ot` (operational technology / ICS)
- `other`

Classification drives sensitive-ingress and blast-radius analysis. It is no
longer inferred solely from the zone name (though legacy name-based inference
still works for v1 profiles).

### Rules

A rule is a 5-tuple of `(source zone, destination zone, protocol, port, action)`.

- `protocol` may be `"any"`.
- `port` may be an integer, a range `"low-high"`, or `"any"`.
- First match wins (configurable via `policy_semantics`; only `first-match`
  is implemented today).
- Absence of a matching rule → **DENY**.

### Reachability graph

ALLOW rules become directed edges. The engine computes:

- Direct adjacency
- Transitive closure (BFS, depth-limited)
- All simple paths from internet-classified zones to sensitive-classified zones
- Per-zone blast radius (reachable set + sensitive targets)

This is the architectural leap from v1 (pattern matching) to v2 (true
segmentation analysis).

### Findings

Findings are pure functions of the profile. They never require network access.

Severity ladder:

| Severity | Typical use |
|---|---|
| HIGH | Almost certainly wrong in a defensive design (direct or transitive sensitive exposure) |
| MEDIUM | Worth fixing; can cause operational or security ambiguity |
| LOW | Informational hygiene (shadowed rules, unclassified IPs) |
| INFO | Pedagogical — reinforces default-deny thinking |

## Extension ideas (future)

- YAML profile support
- Bidirectional rule sugar
- Zone groups / tags
- Additional policy semantics (`deny-overrides`, `allow-union`)
- Export to AWS Security Group / Azure NSG / iptables fragments
- Graphviz / interactive HTML report
- Policy diff between two profiles
- Weighted risk scoring (exposure × sensitivity × hop count × breadth)

## Threat model of the tool itself

The tool only reads a local JSON file and writes a local report. It has no
network surface. The only risk is a malicious profile that tries to exhaust
memory with huge rule lists — profiles are expected to be small design
documents, not production firewall dumps.
