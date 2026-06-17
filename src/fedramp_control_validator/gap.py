"""Gap analysis: turn a scored report into actionable findings.

A "gap" is any assessed control that is not fully satisfied (``fail`` or
``partial``). For each gap we explain *why* it failed by summarising the
non-compliant resources and the Config rules that flagged them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .models import FAIL, PARTIAL, ControlResult, ValidationReport


@dataclass
class Gap:
    """A failing or partially-satisfied control plus the evidence why."""

    control_id: str
    title: str
    family: str
    status: str
    failing_resources: int
    total_resources: int
    rules: List[str]
    reasons: List[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        """A coarse severity used for sorting and dashboard colouring."""
        return "high" if self.status == FAIL else "medium"


def _summarise_reasons(control: ControlResult, max_reasons: int = 8) -> List[str]:
    reasons: List[str] = []
    for finding in control.failing_findings[:max_reasons]:
        detail = finding.annotation or f"{finding.config_rule_name} reported non-compliant"
        reasons.append(f"{finding.resource_id} ({finding.resource_type}): {detail}")
    extra = len(control.failing_findings) - max_reasons
    if extra > 0:
        reasons.append(f"... and {extra} more non-compliant resource(s).")
    return reasons


def build_gaps(report: ValidationReport) -> List[Gap]:
    """Return every failing/partial control as a :class:`Gap`, worst first."""
    gaps: List[Gap] = []
    for control in report.controls:
        if control.status not in (FAIL, PARTIAL):
            continue
        gaps.append(
            Gap(
                control_id=control.control_id,
                title=control.title,
                family=control.family,
                status=control.status,
                failing_resources=control.failing_resources,
                total_resources=control.total_resources,
                rules=control.rules,
                reasons=_summarise_reasons(control),
            )
        )
    # Fails before partials; then by number of failing resources, descending.
    order = {FAIL: 0, PARTIAL: 1}
    gaps.sort(key=lambda g: (order[g.status], -g.failing_resources, g.control_id))
    return gaps


def gap_summary(report: ValidationReport) -> Dict[str, object]:
    """Build a JSON-serialisable gap analysis summary."""
    gaps = build_gaps(report)
    counts = report.counts()
    return {
        "account_id": report.account_id,
        "region": report.region,
        "source": report.source,
        "overall_score": round(report.overall_score * 100, 1),
        "controls_assessed": len(report.assessed_controls),
        "controls_total": len(report.controls),
        "status_counts": counts,
        "families": [
            {
                "family": f.family,
                "title": f.title,
                "status": f.status,
                "score": round(f.score * 100, 1),
                "passing": f.passing,
                "partial": f.partial,
                "failing": f.failing,
            }
            for f in report.families
        ],
        "gaps": [
            {
                "control_id": g.control_id,
                "title": g.title,
                "family": g.family,
                "status": g.status,
                "severity": g.severity,
                "failing_resources": g.failing_resources,
                "total_resources": g.total_resources,
                "rules": g.rules,
                "reasons": g.reasons,
            }
            for g in gaps
        ],
    }
