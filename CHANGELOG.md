# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-08-22

### Added

* **Reachability engine** — builds a directed graph of ALLOW rules and computes
  multi-hop paths. New finding type `TRANSITIVE_SENSITIVE_REACHABILITY` catches
  Internet → sensitive exposure even when no direct rule exists.
* **Explicit zone classifications** (`internet`, `public`, `application`,
  `sensitive`, `management`, `ot`, …). Sensitive detection is no longer
  name-based.
* Port ranges (`"80-443"`) in addition to exact ports and `any`.
* Shadowed-rule detection (`SHADOWED_RULE`).
* Blast-radius summary per zone in the JSON report.
* Mermaid diagrams now reflect *actual* ALLOW edges instead of hard-coded ones.
* Full backward compatibility with v1 `"networks"` profiles (classifications
  are inferred from zone names).
* Richer tests covering transitive paths, port ranges, shadowed rules, and
  legacy config loading.

### Changed

* Version bumped to 2.0.0.
* Development Status classifier set to Beta (more honest given remaining
  modelling limits).
* Report schema includes `reachability` and structured `zones` objects.
* Human output highlights Internet → Sensitive paths.

### Fixed

* Case-sensitivity inconsistencies around zone matching vs sensitivity checks
  eliminated by using the classification enum.

## [1.1.0] — 2026-08-22

### Added

* CIDR overlap / nesting detection.
* Most-specific-match IP classification.
* Support for port `"any"` / `"*"` and protocol `"any"`.
* OVERLY_BROAD_ALLOW, UNCLASSIFIED_IP findings.
* Mermaid zone diagram, short CLI alias `nsa`.
* Expanded test suite, mypy, richer config validation.

## [1.0.0] — 2026-08-22

### Added

* Initial public release.
* CIDR parsing, zone classification, default-deny evaluation.
* Security findings and JSON reporting.
* CLI, tests, CI.
