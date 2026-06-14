"""Smoke tests for EDRGAP. Runs against the bundled demo inventories.

No network access. Pure stdlib + the local package.
"""
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import edrgap
from edrgap import core
from edrgap.cli import main

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic")
AD = os.path.join(DEMO, "ad.csv")
MDM = os.path.join(DEMO, "mdm.json")
EDR = os.path.join(DEMO, "edr.json")

# Fixed clock so the stale-check-in assertion is deterministic.
NOW = datetime(2026, 6, 8, 12, 0, 0, tzinfo=timezone.utc)


def _load_all():
    ad = core.load_inventory(AD, "ad")
    mdm = core.load_inventory(MDM, "mdm")
    edr = core.load_inventory(EDR, "edr")
    return ad, mdm, edr


def test_metadata():
    assert edrgap.TOOL_NAME == "edrgap"
    assert isinstance(edrgap.TOOL_VERSION, str) and edrgap.TOOL_VERSION


def test_inventories_load_and_normalize():
    ad, mdm, edr = _load_all()
    # FQDN in AD must normalize to bare hostname and join with EDR/MDM.
    assert "win-ceo-01" in ad
    assert "win-finance-01" in ad
    assert "win-ceo-01" in mdm
    assert "linux-build-09" in edr


def test_reconcile_finds_expected_gaps():
    ad, mdm, edr = _load_all()
    hosts, findings = core.reconcile(ad, mdm, edr, stale_days=7, now=NOW)
    rules = {(f.hostname, f.rule) for f in findings}

    # Critical: managed but no EDR.
    assert ("win-finance-01", "no_edr_coverage") in rules
    # High: disabled agent.
    assert ("win-hr-02", "agent_degraded") in rules
    # High: stale check-in (~30d old vs fixed clock).
    assert ("win-dev-03", "stale_checkin") in rules
    # Medium: EDR-only rogue host.
    assert ("linux-build-09", "unmanaged_host") in rules
    # Low: in MDM+EDR but not AD.
    assert ("mac-mktg-04", "missing_from_ad") in rules
    # Healthy host produces no findings.
    assert not any(h for (h, _r) in rules if h == "win-ceo-01")


def test_severity_ordering():
    ad, mdm, edr = _load_all()
    _hosts, findings = core.reconcile(ad, mdm, edr, stale_days=7, now=NOW)
    ranks = [core._SEV_RANK[f.severity] for f in findings]
    assert ranks == sorted(ranks), "findings must be sorted by severity"
    assert findings[0].severity == "critical"


def test_summary_counts():
    ad, mdm, edr = _load_all()
    hosts, findings = core.reconcile(ad, mdm, edr, stale_days=7, now=NOW)
    summary = core.summarize(hosts, findings)
    assert summary["total_hosts"] == 6
    assert summary["edr_covered_hosts"] == 5
    assert summary["unprotected_hosts"] == 1
    assert summary["finding_count"] == len(findings)
    assert 0.0 <= summary["coverage_pct"] <= 100.0


def test_cli_exit_nonzero_on_findings(capsys):
    rc = main(["scan", "--ad", AD, "--mdm", MDM, "--edr", EDR])
    out = capsys.readouterr().out
    assert rc == 1  # findings present -> failure exit code
    assert "EDR coverage report" in out
    assert "no_edr_coverage" in out


def test_cli_json_output(capsys):
    import json
    rc = main(["scan", "--ad", AD, "--mdm", MDM, "--edr", EDR, "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 1
    payload = json.loads(out)
    assert payload["tool"] == "edrgap"
    assert payload["summary"]["total_hosts"] == 6
    assert isinstance(payload["findings"], list) and payload["findings"]


def test_cli_clean_run_exits_zero(capsys):
    # Only a single healthy host -> no findings -> exit 0.
    import json
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        ad_p = os.path.join(d, "ad.csv")
        edr_p = os.path.join(d, "edr.json")
        with open(ad_p, "w", encoding="utf-8") as fh:
            fh.write("hostname,os\nWS-1.corp.local,Windows 11\n")
        with open(edr_p, "w", encoding="utf-8") as fh:
            json.dump({"hosts": [{"hostname": "WS-1", "status": "active",
                                  "last_checkin": NOW.isoformat()}]}, fh)
        rc = main(["scan", "--ad", ad_p, "--edr", edr_p])
    assert rc == 0


if __name__ == "__main__":
    test_metadata()
    test_inventories_load_and_normalize()
    test_reconcile_finds_expected_gaps()
    test_severity_ordering()
    test_summary_counts()
    print("ok")
