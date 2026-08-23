"""Command-line interface for Network Segmentation Auditor."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .audit import audit
from .config import load_config
from .report import mermaid_diagram, print_report, save_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network-segmentation-auditor",
        description=(
            "Passive reachability & network-segmentation policy auditor. "
            "Models zones, rules, multi-hop paths and blast radius — no live scanning."
        ),
        epilog="Safety: this tool never discovers hosts, sends packets, or changes firewalls.",
    )
    p.add_argument(
        "-c",
        "--config",
        required=True,
        help="Path to a JSON segmentation profile",
    )
    p.add_argument(
        "-o",
        "--output",
        help="Write full JSON report to this path",
    )
    p.add_argument(
        "--json-only",
        action="store_true",
        help="Suppress human-readable output (JSON only if -o given)",
    )
    p.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 2 when HIGH or MEDIUM findings exist",
    )
    p.add_argument(
        "--mermaid",
        action="store_true",
        help="Also print a Mermaid zone diagram (based on actual ALLOW edges)",
    )
    p.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = load_config(args.config)
        report = audit(profile)

        if args.output:
            save_json(report, args.output)

        if not args.json_only:
            print_report(report)
            if args.mermaid:
                print()
                print(mermaid_diagram(report))

        high = report["summary"].get("HIGH", 0)
        medium = report["summary"].get("MEDIUM", 0)
        if args.exit_code and (high or medium):
            return 2
        return 0

    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover
        print(f"UNEXPECTED ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
