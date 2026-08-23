"""CLI integration tests."""

from __future__ import annotations

import json
from pathlib import Path

from seg_audit.cli import main


def test_cli_safe_exit_zero(tmp_path: Path, capsys) -> None:
    data = {
        "name": "cli-safe",
        "zones": {
            "INTERNET": {"cidr": "0.0.0.0/0", "classification": "internet"},
            "DMZ": {"cidr": "10.0.1.0/24", "classification": "public"},
        },
        "rules": [
            {
                "source": "INTERNET",
                "destination": "DMZ",
                "protocol": "tcp",
                "port": 443,
                "action": "ALLOW",
            }
        ],
    }
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(data))
    out = tmp_path / "report.json"

    code = main(["--config", str(cfg), "--output", str(out), "--exit-code"])
    assert code == 0
    assert out.exists()
    report = json.loads(out.read_text())
    assert report["profile"] == "cli-safe"
    captured = capsys.readouterr()
    assert "Profile" in captured.out


def test_cli_high_finding_exit_two(tmp_path: Path) -> None:
    data = {
        "name": "cli-unsafe",
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
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(data))

    code = main(["--config", str(cfg), "--exit-code", "--json-only"])
    assert code == 2


def test_cli_transitive_high(tmp_path: Path) -> None:
    """Unexpected tiering (no public entry) must fail --exit-code."""
    data = {
        "name": "transitive",
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
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(data))
    code = main(["--config", str(cfg), "--exit-code", "--json-only"])
    assert code == 2


def test_cli_missing_file() -> None:
    code = main(["--config", "/nonexistent/path.json"])
    assert code == 1
