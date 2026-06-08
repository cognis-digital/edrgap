"""EDRGAP command-line interface."""
from cognis_core import build_cli
from edrgap.core import scan, TOOL_NAME, TOOL_VERSION

main = build_cli(
    tool_name=TOOL_NAME,
    tool_version=TOOL_VERSION,
    description="EDR coverage & bypass detector — reconciles MDM + EDR + AD inventories",
    scan_fn=scan,
)

if __name__ == "__main__":
    import sys
    sys.exit(main())
