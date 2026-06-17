"""fedramp-control-validator.

Validate an AWS environment against the FedRAMP Moderate baseline
(NIST SP 800-53 Rev 5) using AWS Config compliance findings, score each
control family, produce a gap analysis, and export OSCAL 1.1.2 Assessment
Results.
"""

from __future__ import annotations

__version__ = "0.1.0"

OSCAL_VERSION = "1.1.2"

__all__ = ["__version__", "OSCAL_VERSION"]
