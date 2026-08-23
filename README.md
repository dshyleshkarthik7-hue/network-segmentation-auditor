# Network Segmentation Auditor

[![CI](https://github.com/dshyleshkarthik7-hue/network-segmentation-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/dshyleshkarthik7-hue/network-segmentation-auditor/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A **passive, configuration-only** Python CLI that models network segmentation
design and answers real reachability questions.

```
CIDR + classification → Zones → ALLOW graph → Multi-hop paths → Findings → JSON / Mermaid
```

> **Safety boundary**  
> This tool never discovers hosts, scans ports, generates packets, or modifies
> firewalls. It only analyses the JSON profile you give it.

---

## Why it exists

A network can be *technically functional* and still be poorly designed from a
security perspective. A flat network makes every compromised workstation far
more valuable than it should be.

Subnetting creates boundaries. **Policy** decides what is allowed to cross them.
**Reachability** tells you what an attacker can actually reach after a breach.

This project turns those ideas into a runnable, testable model you can
experiment with in under a minute.

---

## What is new in 2.0

| Capability | Description |
|---|---|
| **Transitive reachability** | Detects Internet → sensitive paths even when no *direct* rule exists |
| Explicit classifications | Zones declare `internet` / `public` / `sensitive` / `management` / … |
| Port ranges | `"80-443"` in addition to exact ports and `any` |
| Shadowed-rule detection | Flags rules that can never fire |
| Blast-radius summary | Per-zone reachable set and sensitive targets |
| Real Mermaid edges | Diagram reflects actual ALLOW rules |

---

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### Safe example

```bash
network-segmentation-auditor \
  --config examples/safe-web-tier.json \
  --output reports/safe.json \
  --mermaid
```

### Transitive exposure (the key 2.0 demo)

```bash
network-segmentation-auditor \
  --config examples/transitive-exposure.json \
  --exit-code
# → exit code 2  (HIGH: TRANSITIVE_SENSITIVE_REACHABILITY)
```

Short alias: `nsa -c examples/safe-web-tier.json`

---

## Example architecture

```
Internet
   │ HTTPS (443)
   ▼
  DMZ          10.0.1.0/24   (public)
   │ internal API (8443)
   ▼
 Application   10.0.2.0/24   (application)
   │ PostgreSQL (5432)
   ▼
  Data         10.0.3.0/24   (sensitive)

Management     10.0.4.0/24   (management — jump-host only)
```

Even without a direct `INTERNET → DATA` rule, the three ALLOW edges above
create a 3-hop path that v2.0 reports as `TRANSITIVE_SENSITIVE_REACHABILITY`.

---

## Profile schema (v2)

```json
{
  "name": "my-profile",
  "description": "Optional human description",
  "zones": {
    "INTERNET": {
      "cidr": "0.0.0.0/0",
      "classification": "internet"
    },
    "DMZ": {
      "cidr": "10.0.1.0/24",
      "classification": "public"
    },
    "DATA": {
      "cidr": "10.0.3.0/24",
      "classification": "sensitive"
    }
  },
  "sample_ips": {
    "web01": "10.0.1.20",
    "db01": "10.0.3.20"
  },
  "rules": [
    {
      "source": "INTERNET",
      "destination": "DMZ",
      "protocol": "tcp",
      "port": 443,
      "action": "ALLOW",
      "description": "Public HTTPS"
    }
  ],
  "policy_semantics": "first-match"
}
```

* `classification` values: `internet`, `public`, `application`, `sensitive`,
  `management`, `internal`, `ot`, `other`.
* `port` may be an integer, a range `"80-443"`, or `"any"` / `"*"`.
* `protocol` may be `"any"`.
* Rule order matters under `first-match` semantics.
* Missing rules are treated as **DENY**.
* Legacy v1 profiles that use a flat `"networks"` map are still accepted;
  classifications are inferred from zone names.

---

## Finding types

| Severity | Type | Meaning |
|---|---|---|
| HIGH | `INVALID_CIDR` | Zone CIDR cannot be parsed |
| HIGH | `UNKNOWN_ZONE` | Rule references a zone not defined |
| HIGH | `SENSITIVE_INGRESS` | Direct Internet → sensitive ALLOW |
| HIGH | `TRANSITIVE_SENSITIVE_REACHABILITY` | Multi-hop path from Internet to sensitive |
| MEDIUM | `CIDR_OVERLAP` | Two zones share or nest address space |
| MEDIUM | `OVERLY_BROAD_ALLOW` | Internet → zone with any/any |
| LOW | `SHADOWED_RULE` | Rule can never fire |
| LOW | `UNCLASSIFIED_IP` | Sample IP falls outside every zone |
| INFO | `NO_EXPLICIT_RULE` | No rule exists for a zone pair (default-deny) |

---

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
mypy seg_audit
```

CI runs on Ubuntu + Windows across Python 3.9–3.13.

---

## Safety & scope

* **In scope**: static analysis of a segmentation *design*, including multi-hop
  reachability under the modelled rules.
* **Out of scope**: live network discovery, port scanning, packet injection,
  firewall push, cloud API mutation, NAT, stateful inspection, routing tables,
  or host firewalls.

The tool answers: “Given *this* abstract policy, what can reach what?”  
It does **not** claim that a missing rule means traffic is impossible on a
real network that may have other paths or controls.

For production enforcement use real firewalls, cloud security groups, NAC, or
micro-segmentation platforms. This tool is for learning, design review, and CI
checks on policy-as-code.

---

## Project layout

```
network-segmentation-auditor/
├── seg_audit/          # library + CLI
│   ├── models.py       # Zone, Rule, Profile, Classification
│   ├── cidr.py
│   ├── policy.py
│   ├── graph.py        # reachability engine (v2)
│   ├── audit.py
│   ├── config.py
│   ├── report.py
│   └── cli.py
├── examples/           # ready-to-run profiles
├── tests/
├── docs/
├── .github/workflows/
├── pyproject.toml
├── README.md
├── CHANGELOG.md
└── LICENSE
```

---

## Licence

MIT — see [LICENSE](LICENSE).
