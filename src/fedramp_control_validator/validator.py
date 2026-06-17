"""The scoring engine.

Given a :class:`FindingSet`, score every catalog control (pass / fail /
partial / not-assessed) and roll those up into per-family scores and an
overall :class:`ValidationReport`.

Scoring rules for a single control:

* Gather every *evaluated* finding (COMPLIANT or NON_COMPLIANT) whose Config
  rule maps to the control.
* No evaluated findings  -> ``not-assessed``
* All findings compliant -> ``pass``
* All findings failing   -> ``fail``
* A mix of the two       -> ``partial``

A family rolls up its assessed controls the same way: all pass -> ``pass``,
all fail -> ``fail``, otherwise ``partial`` (and ``not-assessed`` if no control
in the family had any evidence).
"""

from __future__ import annotations

from typing import Dict, List

from .catalog import (
    CONTROL_CATALOG,
    control_rule_index,
    control_title,
    family_of,
    family_title,
)
from .models import (
    FAIL,
    NOT_ASSESSED,
    PARTIAL,
    PASS,
    ControlResult,
    FamilyScore,
    Finding,
    FindingSet,
    ValidationReport,
)


def _group_findings_by_rule(findings: List[Finding]) -> Dict[str, List[Finding]]:
    grouped: Dict[str, List[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.config_rule_name, []).append(finding)
    return grouped


def _score_control(
    control_id: str,
    rules: List[str],
    findings_by_rule: Dict[str, List[Finding]],
) -> ControlResult:
    result = ControlResult(
        control_id=control_id,
        title=control_title(control_id),
        family=family_of(control_id),
        rules=sorted(rules),
    )

    for rule in rules:
        for finding in findings_by_rule.get(rule, []):
            if not finding.is_evaluated:
                continue
            result.total_resources += 1
            if finding.is_compliant:
                result.passing_resources += 1
            else:
                result.failing_resources += 1
                result.failing_findings.append(finding)

    if result.total_resources == 0:
        result.status = NOT_ASSESSED
    elif result.failing_resources == 0:
        result.status = PASS
    elif result.passing_resources == 0:
        result.status = FAIL
    else:
        result.status = PARTIAL
    return result


def _roll_up_family(controls: List[ControlResult]) -> str:
    assessed = [c for c in controls if c.status != NOT_ASSESSED]
    if not assessed:
        return NOT_ASSESSED
    statuses = {c.status for c in assessed}
    if statuses == {PASS}:
        return PASS
    if statuses == {FAIL}:
        return FAIL
    return PARTIAL


def validate(finding_set: FindingSet) -> ValidationReport:
    """Score a :class:`FindingSet` into a full :class:`ValidationReport`."""
    findings_by_rule = _group_findings_by_rule(finding_set.findings)
    index = control_rule_index()

    # Score every control in the catalog (even those with no evidence so the
    # gap analysis can surface them as not-assessed).
    results: List[ControlResult] = []
    for control_id in CONTROL_CATALOG:
        rules = sorted(index.get(control_id, set()))
        results.append(_score_control(control_id, rules, findings_by_rule))

    # Group into families.
    by_family: Dict[str, List[ControlResult]] = {}
    for result in results:
        by_family.setdefault(result.family, []).append(result)

    families: List[FamilyScore] = []
    for family in sorted(by_family):
        controls = sorted(by_family[family], key=lambda c: _control_sort_key(c.control_id))
        families.append(
            FamilyScore(
                family=family,
                title=family_title(family),
                status=_roll_up_family(controls),
                controls=controls,
            )
        )

    evaluated = sum(1 for f in finding_set.findings if f.is_evaluated)
    return ValidationReport(
        account_id=finding_set.account_id,
        region=finding_set.region,
        source=finding_set.source,
        families=families,
        findings_evaluated=evaluated,
    )


def _control_sort_key(control_id: str):
    """Sort controls numerically within a family (AC-2 before AC-17)."""
    family, _, number = control_id.partition("-")
    try:
        return (family, int(number))
    except ValueError:
        return (family, 0)
