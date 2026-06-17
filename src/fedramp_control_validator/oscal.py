"""Export a :class:`ValidationReport` as OSCAL 1.1.2 Assessment Results.

The output conforms to the structure of the OSCAL Assessment Results model
(``assessment-results``) as defined by NIST OSCAL 1.1.2. Each scored control
becomes a *finding* whose target objective status is ``satisfied`` or
``not-satisfied``; each non-compliant AWS Config evaluation becomes an
*observation* providing the underlying evidence.

Control ids are emitted in OSCAL's lower-case dotted form (``ac-2``) and the
catalog is referenced as the FedRAMP Rev 5 Moderate profile.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from . import OSCAL_VERSION, __version__
from .models import FAIL, NOT_ASSESSED, PASS, ControlResult, ValidationReport

FEDRAMP_MODERATE_PROFILE = (
    "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/"
    "rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json"
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _deterministic_uuid(*parts: str) -> str:
    """Stable UUID5 so repeated exports of the same data diff cleanly."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "::".join(parts)))


def _oscal_control_id(control_id: str) -> str:
    return control_id.lower()


def _observations_for_control(control: ControlResult, result_uuid: str) -> List[Dict[str, Any]]:
    observations: List[Dict[str, Any]] = []
    for finding in control.failing_findings:
        obs_uuid = _deterministic_uuid(
            result_uuid, control.control_id, finding.config_rule_name, finding.resource_id
        )
        observations.append(
            {
                "uuid": obs_uuid,
                "title": f"AWS Config: {finding.config_rule_name}",
                "description": (
                    finding.annotation
                    or f"Resource {finding.resource_id} is non-compliant with "
                    f"{finding.config_rule_name}."
                ),
                "methods": ["TEST"],
                "types": ["finding"],
                "subjects": [
                    {
                        "subject-uuid": _deterministic_uuid(finding.resource_id, finding.resource_type),
                        "type": "component",
                        "title": finding.resource_id,
                        "props": [
                            {"name": "resource-type", "value": finding.resource_type},
                            {"name": "config-rule", "value": finding.config_rule_name},
                            {"name": "compliance", "value": finding.compliance_type},
                        ],
                    }
                ],
                "collected": _now(),
            }
        )
    return observations


def _finding_for_control(control: ControlResult, result_uuid: str) -> Dict[str, Any]:
    state = "satisfied" if control.status == PASS else "not-satisfied"
    description = (
        f"{control.control_id} ({control.title}): {control.passing_resources} of "
        f"{control.total_resources} evaluated resources are compliant "
        f"[{control.status}]."
    )
    return {
        "uuid": _deterministic_uuid(result_uuid, "finding", control.control_id),
        "title": f"{control.control_id} {control.title}",
        "description": description,
        "props": [
            {"name": "status", "value": control.status},
            {"name": "passing-resources", "value": str(control.passing_resources)},
            {"name": "failing-resources", "value": str(control.failing_resources)},
        ],
        "target": {
            "type": "objective-id",
            "target-id": f"{_oscal_control_id(control.control_id)}_obj",
            "title": f"Objective for {control.control_id}",
            "status": {"state": state},
        },
        "related-observations": [
            {"observation-uuid": _deterministic_uuid(
                result_uuid, control.control_id, f.config_rule_name, f.resource_id
            )}
            for f in control.failing_findings
        ],
    }


def to_oscal(report: ValidationReport, title: str = "FedRAMP Moderate Automated Assessment") -> Dict[str, Any]:
    """Render a :class:`ValidationReport` as an OSCAL assessment-results doc."""
    now = _now()
    doc_uuid = _deterministic_uuid("assessment-results", report.account_id, report.source)
    result_uuid = _deterministic_uuid("result", report.account_id, report.source)

    assessed_controls = report.assessed_controls

    control_selections = [
        {"control-id": _oscal_control_id(c.control_id)} for c in assessed_controls
    ]

    findings: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    for control in assessed_controls:
        findings.append(_finding_for_control(control, result_uuid))
        observations.extend(_observations_for_control(control, result_uuid))

    counts = report.counts()

    result: Dict[str, Any] = {
        "uuid": result_uuid,
        "title": "FedRAMP Moderate control validation",
        "description": (
            f"Automated validation of AWS account {report.account_id} ({report.region}) "
            f"against the FedRAMP Moderate baseline. Overall score "
            f"{round(report.overall_score * 100, 1)}%."
        ),
        "start": now,
        "end": now,
        "props": [
            {"name": "overall-score", "value": str(round(report.overall_score * 100, 1))},
            {"name": "controls-passing", "value": str(counts[PASS])},
            {"name": "controls-failing", "value": str(counts[FAIL])},
            {"name": "controls-not-assessed", "value": str(counts[NOT_ASSESSED])},
        ],
        "reviewed-controls": {
            "control-selections": [
                {
                    "description": "Controls evaluated from AWS Config compliance data.",
                    "include-controls": control_selections,
                }
            ]
        },
    }
    if observations:
        result["observations"] = observations
    if findings:
        result["findings"] = findings

    return {
        "assessment-results": {
            "uuid": doc_uuid,
            "metadata": {
                "title": title,
                "last-modified": now,
                "version": __version__,
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {"name": "aws-account-id", "value": report.account_id},
                    {"name": "aws-region", "value": report.region},
                ],
                "roles": [
                    {"id": "assessor", "title": "Automated Assessor"},
                ],
                "parties": [
                    {
                        "uuid": _deterministic_uuid("party", "fedramp-control-validator"),
                        "type": "organization",
                        "name": "fedramp-control-validator",
                    }
                ],
            },
            "import-ap": {"href": FEDRAMP_MODERATE_PROFILE},
            "results": [result],
        }
    }
