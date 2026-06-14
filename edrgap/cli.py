"""Command-line interface for EDRGAP."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import load_inventory, reconcile, summarize, SEVERITY_ORDER

_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=("EDR coverage & bypass detector -- reconciles MDM, EDR "
                     "and Active Directory host inventories to find endpoints "
                     "with missing, stale, or degraded EDR protection."),
        epilog=("Example:\n"
                "  edrgap scan --ad ad.csv --mdm mdm.json --edr edr.json\n"
                "  edrgap scan --edr edr.json --ad ad.csv --format json\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="Reconcile inventories and report coverage gaps.",
        description="Reconcile AD/MDM/EDR inventories and report coverage gaps.",
    )
    scan.add_argument("--ad", metavar="FILE",
                      help="Active Directory host inventory (CSV or JSON).")
    scan.add_argument("--mdm", metavar="FILE",
                      help="MDM device inventory (CSV or JSON).")
    scan.add_argument("--edr", metavar="FILE",
                      help="EDR agent inventory (CSV or JSON).")
    scan.add_argument("--stale-days", type=int, default=7,
                      help="Days since last EDR check-in to flag as stale "
                           "(default: 7).")
    scan.add_argument("--min-severity", choices=SEVERITY_ORDER, default="info",
                      help="Only report findings at or above this severity.")
    scan.add_argument("--format", choices=("table", "json"), default="table",
                      help="Output format (default: table).")
    return p


def _render_table(hosts, findings, summary) -> str:
    lines: List[str] = []
    lines.append("=" * 64)
    lines.append(f"  {TOOL_NAME} {TOOL_VERSION} -- EDR coverage report")
    lines.append("=" * 64)
    lines.append(f"  Hosts seen          : {summary['total_hosts']}")
    lines.append(f"  Managed (AD/MDM)    : {summary['managed_hosts']}")
    lines.append(f"  EDR-covered         : {summary['edr_covered_hosts']}")
    lines.append(f"  Unprotected         : {summary['unprotected_hosts']}")
    lines.append(f"  EDR coverage        : {summary['coverage_pct']}%")
    lines.append(f"  Findings            : {summary['finding_count']}")
    sev = summary["findings_by_severity"]
    sev_str = "  ".join(f"{s}:{sev[s]}" for s in SEVERITY_ORDER if sev[s])
    lines.append(f"  By severity         : {sev_str or 'none'}")
    lines.append("")
    if not findings:
        lines.append("  No findings. All managed hosts have healthy EDR.")
        return "\n".join(lines)
    lines.append(f"  {'SEVERITY':<9} {'RULE':<18} {'HOST':<22} DETAIL")
    lines.append("  " + "-" * 60)
    for f in findings:
        msg = f.message
        if len(msg) > 60:
            msg = msg[:57] + "..."
        lines.append(f"  {f.severity:<9} {f.rule:<18} {f.hostname:<22} {msg}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("\nerror: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 2


def _main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 0

    if not (args.ad or args.mdm or args.edr):
        parser.error("provide at least one of --ad / --mdm / --edr")

    if args.stale_days < 1:
        print(
            f"error: --stale-days must be a positive integer, got {args.stale_days}",
            file=sys.stderr,
        )
        return 2

    try:
        ad = load_inventory(args.ad, "ad") if args.ad else {}
        mdm = load_inventory(args.mdm, "mdm") if args.mdm else {}
        edr = load_inventory(args.edr, "edr") if args.edr else {}
    except FileNotFoundError as exc:
        print(f"error: cannot open inventory file: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"error: failed to parse inventory: {exc}", file=sys.stderr)
        return 2

    try:
        hosts, findings = reconcile(ad, mdm, edr, stale_days=args.stale_days)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    threshold = _SEV_RANK[args.min_severity]
    findings = [f for f in findings if _SEV_RANK.get(f.severity, 99) <= threshold]
    summary = summarize(hosts, findings)

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "summary": summary,
            "hosts": [h.to_dict() for h in hosts],
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_render_table(hosts, findings, summary))

    # Non-zero exit when any finding is present (coverage gap == failure).
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
