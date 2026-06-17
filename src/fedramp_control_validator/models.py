"""Data models shared across the validator.

These are intentionally lightweight dataclasses so the scoring engine, the
OSCAL exporter, the CLI, and the Streamlit dashboard can all share the same
vocabulary without pulling in a heavier framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Status vocabulary
# ---------------------------------------------------------------------------

#: A control (or family) is fully satisfied by the available evidence.
PASS = "pass"
#: Every relevant resource failed; the control is not satisfied at all.
FAIL = "fail"
#: Some relevant resources pass and some fail.
PARTIAL = "partial"
#: No findings mapped to the control, so it could not be evaluated.
NOT_ASSESSED = "not-assessed"

#: Ordering used when a family rolls up several control statuses.
STATUS_SEVERITY = {PASS: 0, NOT_ASSESSED: 1, PARTIAL: 2, FAIL: 3}

#: AWS Config compliance values that count as a passing evaluation.
COMPLIANT = "COMPLIANT"
#: AWS Config compliance values that count as a failing evaluation.
NON_COMPLIANT = "NON_COMPLIANT"


@dataclass
class Finding:
    """A single AWS Config rule evaluation against one resource.

    Attributes:
        config_rule_name: AWS Config managed/custom rule name, e.g.
            ``s3-bucket-server-side-encryption-enabled``.
        resource_type: CloudFormation-style type, e.g. ``AWS::S3::Bucket``.
        resource_id: Physical resource id (bucket name, instance id, ...).
        compliance_type: ``COMPLIANT``, ``NON_COMPLIANT``, ``NOT_APPLICABLE``
            or ``INSUFFICIENT_DATA``.
        annotation: Free-text reason captured by the rule, when present.
        region: AWS region the resource lives in, when known.
    """

    config_rule_name: str
    resource_type: str = "AWS::::Account"
    resource_id: str = "unknown"
    compliance_type: str = NON_COMPLIANT
    annotation: Optional[str] = None
    region: Optional[str] = None

    @property
    def is_compliant(self) -> bool:
        return self.compliance_type.upper() == COMPLIANT

    @property
    def is_non_compliant(self) -> bool:
        return self.compliance_type.upper() == NON_COMPLIANT

    @property
    def is_evaluated(self) -> bool:
        """True when the finding contributes a pass/fail signal."""
        return self.is_compliant or self.is_non_compliant


@dataclass
class FindingSet:
    """A parsed batch of AWS Config findings plus environment metadata."""

    findings: List[Finding] = field(default_factory=list)
    account_id: str = "000000000000"
    region: str = "us-east-1"
    source: str = "unknown"

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.findings)


@dataclass
class ControlResult:
    """Scored outcome for a single NIST 800-53 control."""

    control_id: str
    title: str
    family: str
    status: str = NOT_ASSESSED
    rules: List[str] = field(default_factory=list)
    total_resources: int = 0
    failing_resources: int = 0
    passing_resources: int = 0
    failing_findings: List[Finding] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Fraction of evaluated resources that passed (0.0 - 1.0)."""
        if self.total_resources == 0:
            return 0.0
        return self.passing_resources / self.total_resources


@dataclass
class FamilyScore:
    """Roll-up of every assessed control within a control family."""

    family: str
    title: str
    status: str = NOT_ASSESSED
    controls: List[ControlResult] = field(default_factory=list)

    @property
    def assessed_controls(self) -> List[ControlResult]:
        return [c for c in self.controls if c.status != NOT_ASSESSED]

    @property
    def score(self) -> float:
        """Weighted family score where partial counts as half (0.0 - 1.0)."""
        assessed = self.assessed_controls
        if not assessed:
            return 0.0
        points = 0.0
        for control in assessed:
            if control.status == PASS:
                points += 1.0
            elif control.status == PARTIAL:
                points += 0.5
        return points / len(assessed)

    @property
    def passing(self) -> int:
        return sum(1 for c in self.controls if c.status == PASS)

    @property
    def failing(self) -> int:
        return sum(1 for c in self.controls if c.status == FAIL)

    @property
    def partial(self) -> int:
        return sum(1 for c in self.controls if c.status == PARTIAL)


@dataclass
class ValidationReport:
    """The complete scored assessment for an environment."""

    account_id: str
    region: str
    source: str
    families: List[FamilyScore] = field(default_factory=list)
    findings_evaluated: int = 0

    @property
    def controls(self) -> List[ControlResult]:
        out: List[ControlResult] = []
        for family in self.families:
            out.extend(family.controls)
        return out

    @property
    def assessed_controls(self) -> List[ControlResult]:
        return [c for c in self.controls if c.status != NOT_ASSESSED]

    @property
    def overall_score(self) -> float:
        assessed = self.assessed_controls
        if not assessed:
            return 0.0
        points = 0.0
        for control in assessed:
            if control.status == PASS:
                points += 1.0
            elif control.status == PARTIAL:
                points += 0.5
        return points / len(assessed)

    def counts(self) -> Dict[str, int]:
        """Return a status -> count tally across all controls."""
        tally = {PASS: 0, FAIL: 0, PARTIAL: 0, NOT_ASSESSED: 0}
        for control in self.controls:
            tally[control.status] += 1
        return tally
