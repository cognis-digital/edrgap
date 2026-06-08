"""EDRGAP — inventory diff scanner."""
from __future__ import annotations
import csv, time
from pathlib import Path
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "EDRGAP"
TOOL_VERSION = "0.1.0"

def scan(target: str, **opts) -> ScanResult:
    """target = directory containing `source-of-truth.csv` and `endpoint-protection.csv`."""
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    p = Path(target)
    sot = p / "source-of-truth.csv"
    ep  = p / "endpoint-protection.csv"
    if not (sot.is_file() and ep.is_file()):
        return result
    def col(path, key="hostname"):
        with path.open() as f:
            return {row[key].strip().lower() for row in csv.DictReader(f) if row.get(key)}
    truth = col(sot)
    covered = col(ep)
    gap = truth - covered
    result.items_scanned = len(truth)
    for host in sorted(gap):
        result.add(Finding(
            id=f"INV-GAP-{abs(hash(host))%10000:04d}",
            severity="high", weight=2.5,
            title="ENDPOINT_GAP",
            description=f"Device {host!r} present in source-of-truth but missing from endpoint-protection inventory.",
            location=str(ep), category="coverage-gap",
            remediation="Enroll endpoint in EDR/MDM. Investigate why it was missed.",
        ))
    result.metadata.update(devices_in_truth=len(truth), devices_covered=len(covered), gap_count=len(gap))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time()-t0)*1000)
    return result
