"""Hardening tests — edge cases, bad input, and error-path coverage."""
from __future__ import annotations

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from edrgap import core
from edrgap.cli import main


# ---------------------------------------------------------------------------
# load_inventory edge cases
# ---------------------------------------------------------------------------

def test_missing_file_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        core.load_inventory("/nonexistent/path/that/does/not/exist.json", "edr")


def test_empty_json_array_returns_empty_dict(tmp_path):
    f = tmp_path / "empty.json"
    f.write_text("[]", encoding="utf-8")
    result = core.load_inventory(str(f), "edr")
    assert result == {}


def test_empty_csv_returns_empty_dict(tmp_path):
    f = tmp_path / "empty.csv"
    f.write_text("hostname,os\n", encoding="utf-8")  # header only, no rows
    result = core.load_inventory(str(f), "ad")
    assert result == {}


def test_malformed_json_raises_value_error(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text('{"hosts": [{"hostname": "ws1"', encoding="utf-8")  # truncated
    with pytest.raises(ValueError, match="invalid JSON"):
        core.load_inventory(str(f), "edr")


def test_rows_without_hostname_are_skipped(tmp_path):
    """Rows missing a recognized hostname key must be silently skipped."""
    data = [{"ip": "10.0.0.1", "os": "Windows"}, {"hostname": "ws1", "os": "Linux"}]
    f = tmp_path / "partial.json"
    f.write_text(json.dumps(data), encoding="utf-8")
    result = core.load_inventory(str(f), "mdm")
    assert "ws1" in result
    assert len(result) == 1


def test_empty_path_raises_value_error():
    with pytest.raises(ValueError, match="path must not be empty"):
        core.load_inventory("", "ad")


# ---------------------------------------------------------------------------
# reconcile validation
# ---------------------------------------------------------------------------

def test_reconcile_rejects_zero_stale_days():
    with pytest.raises(ValueError, match="stale_days"):
        core.reconcile(stale_days=0)


def test_reconcile_rejects_negative_stale_days():
    with pytest.raises(ValueError, match="stale_days"):
        core.reconcile(stale_days=-5)


def test_reconcile_all_empty_inventories():
    """Empty inventories must produce zero hosts and zero findings."""
    hosts, findings = core.reconcile({}, {}, {}, stale_days=7)
    assert hosts == []
    assert findings == []


def test_reconcile_edr_only_empty():
    """reconcile called with all defaults (no inventories) must not crash."""
    hosts, findings = core.reconcile()
    assert isinstance(hosts, list)
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# CLI error paths
# ---------------------------------------------------------------------------

def test_cli_missing_file_returns_exit_2(capsys):
    rc = main(["scan", "--edr", "/no/such/file.json"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "error" in err.lower()


def test_cli_malformed_json_returns_exit_2(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{oops}", encoding="utf-8")
    rc = main(["scan", "--edr", str(bad)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "error" in err.lower()


def test_cli_zero_stale_days_returns_exit_2(capsys, tmp_path):
    f = tmp_path / "edr.json"
    f.write_text("[]", encoding="utf-8")
    rc = main(["scan", "--edr", str(f), "--stale-days", "0"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "stale-days" in err or "stale_days" in err


def test_cli_negative_stale_days_returns_exit_2(capsys, tmp_path):
    f = tmp_path / "edr.json"
    f.write_text("[]", encoding="utf-8")
    rc = main(["scan", "--edr", str(f), "--stale-days", "-3"])
    capsys.readouterr()
    assert rc == 2


def test_cli_no_args_exits_zero(capsys):
    """Invoking with no subcommand should print help and exit 0."""
    rc = main([])
    assert rc == 0


def test_cli_empty_edr_no_findings(capsys, tmp_path):
    """An empty EDR inventory with no AD/MDM produces zero findings, exit 0."""
    f = tmp_path / "edr.json"
    f.write_text("[]", encoding="utf-8")
    rc = main(["scan", "--edr", str(f)])
    assert rc == 0
