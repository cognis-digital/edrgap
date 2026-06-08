"""
EDRGAP — EDR coverage & bypass detector — reconciles MDM + EDR + AD inventories
Part of the Cognis Neural Suite by Cognis Digital.
https://cognis.digital · MIT License
"""
from edrgap.core import scan, TOOL_NAME, TOOL_VERSION

__version__ = TOOL_VERSION
__author__ = "Cognis Digital"
__license__ = "MIT"
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION", "__version__"]
