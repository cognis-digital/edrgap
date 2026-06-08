"""EDRGAP - EDR coverage & bypass detector.

Reconciles MDM, EDR, and Active Directory (AD) host inventories to surface
endpoints that lack EDR coverage, are stale/not-reporting, or appear in some
inventories but not others (a classic blue-team blind spot).

Standard library only. Zero install.
"""
from .core import (
    Host,
    Finding,
    load_inventory,
    reconcile,
    summarize,
    SEVERITY_ORDER,
)

TOOL_NAME = "edrgap"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Host",
    "Finding",
    "load_inventory",
    "reconcile",
    "summarize",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "TOOL_VERSION",
]
