"""Core reconciliation engine for EDRGAP.

The engine ingests up to three host inventories (AD, MDM, EDR), normalizes
hostnames, joins them, and emits findings describing coverage gaps and
bypass-prone conditions.

Input formats accepted (auto-detected):
  * JSON  : a list of objects, OR an object with a top-level list under one of
            'hosts'/'devices'/'rows'/'data'.
  * CSV   : header row + rows.

Recognized (case-insensitive) field aliases per source are normalized to a
common Host record. Unknown fields are ignored.
"""
from __future__ import annotations

import csv
import io
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Severity ordering, highest first. Used for sorting + exit-code policy.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Field aliases mapped to canonical keys.
_HOSTNAME_KEYS = ("hostname", "host", "name", "computername", "computer_name",
                  "device_name", "devicename", "machine", "dnshostname")
_LASTSEEN_KEYS = ("last_seen", "lastseen", "last_checkin", "lastcheckin",
                  "last_sync", "lastsync", "last_logon", "lastlogon",
                  "last_contact", "timestamp")
_AGENT_KEYS = ("edr_agent", "agent", "agent_version", "sensor_version",
               "edr_version", "version")
_STATUS_KEYS = ("status", "agent_status", "sensor_status", "health",
                "agent_health")
_OS_KEYS = ("os", "platform", "operating_system", "os_platform")


def _norm_host(name: str) -> str:
    """Normalize a hostname for joining: strip domain, lowercase, trim."""
    if not name:
        return ""
    n = str(name).strip().lower()
    # Drop a trailing dollar (AD machine accounts) and FQDN domain part.
    n = n.rstrip("$")
    if "." in n:
        n = n.split(".", 1)[0]
    return n


def _first(d: Dict[str, Any], keys: Iterable[str]) -> Optional[Any]:
    lowered = {k.lower(): v for k, v in d.items()}
    for k in keys:
        if k in lowered and lowered[k] not in (None, ""):
            return lowered[k]
    return None


def _parse_dt(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        # Treat as epoch seconds.
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip().replace("Z", "+00:00")
    fmts = (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%m/%d/%Y",
    )
    for fmt in fmts:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # Last resort: fromisoformat.
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


@dataclass
class Host:
    """A reconciled view of one endpoint across inventories."""
    hostname: str
    in_ad: bool = False
    in_mdm: bool = False
    in_edr: bool = False
    os: str = ""
    edr_agent: str = ""
    edr_status: str = ""
    last_seen: Optional[str] = None  # ISO string of most recent EDR contact

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    hostname: str
    rule: str
    severity: str
    message: str
    sources: Dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _detect_and_load(text: str) -> List[Dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    if text[0] in "[{":
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("hosts", "devices", "rows", "data", "results"):
                if isinstance(data.get(key), list):
                    return [r for r in data[key] if isinstance(r, dict)]
            # Single object -> one row.
            return [data]
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        return []
    # Assume CSV.
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


def load_inventory(path: str, source: str) -> Dict[str, Dict[str, Any]]:
    """Load one inventory file. Returns {normalized_hostname: raw_fields}.

    ``source`` is one of 'ad', 'mdm', 'edr' (used only for messaging).
    """
    with open(path, "r", encoding="utf-8-sig") as fh:
        rows = _detect_and_load(fh.read())
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        raw = _first(row, _HOSTNAME_KEYS)
        host = _norm_host(raw) if raw is not None else ""
        if not host:
            continue
        out[host] = row
    return out


def _is_stale(last_seen: Optional[datetime], now: datetime, days: int) -> bool:
    if last_seen is None:
        return False
    return (now - last_seen).total_seconds() > days * 86400


def reconcile(
    ad: Optional[Dict[str, Dict[str, Any]]] = None,
    mdm: Optional[Dict[str, Dict[str, Any]]] = None,
    edr: Optional[Dict[str, Dict[str, Any]]] = None,
    stale_days: int = 7,
    now: Optional[datetime] = None,
) -> Tuple[List[Host], List[Finding]]:
    """Join the inventories and produce hosts + findings.

    Coverage logic:
      * A host known to AD or MDM but absent from EDR is UNPROTECTED.
      * A host in EDR whose last check-in is older than ``stale_days`` is
        STALE (potentially evading / powered off / bypassed).
      * A host in EDR with a disabled/unhealthy agent status is DEGRADED.
      * A host present only in EDR (not in AD or MDM) is UNMANAGED/rogue.
    """
    ad = ad or {}
    mdm = mdm or {}
    edr = edr or {}
    now = now or datetime.now(timezone.utc)

    all_names = set(ad) | set(mdm) | set(edr)
    hosts: List[Host] = []
    findings: List[Finding] = []

    _bad_status = {"disabled", "inactive", "offline", "unhealthy", "error",
                   "degraded", "uninstalled", "stopped", "not reporting"}

    for name in sorted(all_names):
        in_ad = name in ad
        in_mdm = name in mdm
        in_edr = name in edr
        edr_row = edr.get(name, {})

        os_val = (_first(ad.get(name, {}), _OS_KEYS)
                  or _first(mdm.get(name, {}), _OS_KEYS)
                  or _first(edr_row, _OS_KEYS) or "")
        agent = _first(edr_row, _AGENT_KEYS) or ""
        status = (_first(edr_row, _STATUS_KEYS) or "")
        last_dt = _parse_dt(_first(edr_row, _LASTSEEN_KEYS))

        host = Host(
            hostname=name,
            in_ad=in_ad,
            in_mdm=in_mdm,
            in_edr=in_edr,
            os=str(os_val),
            edr_agent=str(agent),
            edr_status=str(status),
            last_seen=last_dt.isoformat() if last_dt else None,
        )
        hosts.append(host)

        sources = {"ad": in_ad, "mdm": in_mdm, "edr": in_edr}

        # Rule: managed asset with no EDR coverage at all.
        if (in_ad or in_mdm) and not in_edr:
            mgr = "AD" if in_ad else ""
            if in_mdm:
                mgr = (mgr + "+MDM") if mgr else "MDM"
            findings.append(Finding(
                hostname=name,
                rule="no_edr_coverage",
                severity="critical",
                message=(f"Host is in {mgr} inventory but has no EDR agent "
                         f"-- unprotected attack surface."),
                sources=sources,
            ))
            # No further EDR-state rules apply if there is no EDR record.
            continue

        if in_edr:
            # Rule: rogue / unmanaged host only EDR knows about.
            if not in_ad and not in_mdm:
                findings.append(Finding(
                    hostname=name,
                    rule="unmanaged_host",
                    severity="medium",
                    message=("Host reports to EDR but is absent from AD and "
                             "MDM -- unmanaged/rogue or decommissioned."),
                    sources=sources,
                ))

            # Rule: degraded/disabled agent.
            if status and status.strip().lower() in _bad_status:
                findings.append(Finding(
                    hostname=name,
                    rule="agent_degraded",
                    severity="high",
                    message=(f"EDR agent status is '{status}' -- protection "
                             f"may be disabled or bypassed."),
                    sources=sources,
                ))

            # Rule: stale check-in.
            if _is_stale(last_dt, now, stale_days):
                age = int((now - last_dt).total_seconds() // 86400)
                findings.append(Finding(
                    hostname=name,
                    rule="stale_checkin",
                    severity="high",
                    message=(f"EDR last check-in was {age}d ago "
                             f"(>{stale_days}d) -- agent may be silenced."),
                    sources=sources,
                ))
            elif last_dt is None and not status:
                findings.append(Finding(
                    hostname=name,
                    rule="unknown_state",
                    severity="low",
                    message=("EDR record lacks last-seen and status fields -- "
                             "cannot confirm the agent is reporting."),
                    sources=sources,
                ))

            # Rule: in EDR + MDM but missing from AD (shadow / off-domain).
            if in_mdm and not in_ad:
                findings.append(Finding(
                    hostname=name,
                    rule="missing_from_ad",
                    severity="low",
                    message=("Host is in MDM+EDR but not in AD -- off-domain "
                             "or out-of-sync directory record."),
                    sources=sources,
                ))

    findings.sort(key=lambda f: (_SEV_RANK.get(f.severity, 99), f.hostname))
    return hosts, findings


def summarize(hosts: List[Host], findings: List[Finding]) -> Dict[str, Any]:
    """Build a machine-readable summary of the reconciliation."""
    total = len(hosts)
    covered = sum(1 for h in hosts if h.in_edr)
    managed = sum(1 for h in hosts if h.in_ad or h.in_mdm)
    unprotected = sum(1 for h in hosts if (h.in_ad or h.in_mdm) and not h.in_edr)
    coverage_pct = round(100.0 * covered / total, 1) if total else 0.0
    by_sev: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    by_rule: Dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
    return {
        "total_hosts": total,
        "managed_hosts": managed,
        "edr_covered_hosts": covered,
        "unprotected_hosts": unprotected,
        "coverage_pct": coverage_pct,
        "finding_count": len(findings),
        "findings_by_severity": by_sev,
        "findings_by_rule": by_rule,
    }
