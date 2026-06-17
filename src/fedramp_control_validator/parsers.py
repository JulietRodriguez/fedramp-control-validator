"""Parse AWS Config compliance findings into a :class:`FindingSet`.

Two input shapes are supported:

1. The tool's own simplified shape (what the bundled samples use)::

       {
         "account_id": "123456789012",
         "region": "us-east-1",
         "findings": [
           {
             "config_rule_name": "s3-bucket-server-side-encryption-enabled",
             "resource_type": "AWS::S3::Bucket",
             "resource_id": "app-data",
             "compliance_type": "NON_COMPLIANT",
             "annotation": "Default encryption is not enabled."
           }
         ]
       }

2. The native AWS CLI shape returned by
   ``aws configservice get-compliance-details-by-config-rule`` /
   ``describe-compliance-by-resource`` (a list of ``EvaluationResults``).

A bare JSON list of finding objects is also accepted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Union

from .models import Finding, FindingSet


class ParseError(Exception):
    """Raised when an input document cannot be parsed into findings."""


def _coerce_finding(raw: Dict[str, Any]) -> Finding:
    """Build a :class:`Finding` from either supported finding shape."""
    if "EvaluationResultIdentifier" in raw or "ComplianceType" in raw:
        return _coerce_native_finding(raw)
    return Finding(
        config_rule_name=raw.get("config_rule_name") or raw.get("rule") or "unknown-rule",
        resource_type=raw.get("resource_type", "AWS::::Account"),
        resource_id=raw.get("resource_id", "unknown"),
        compliance_type=str(raw.get("compliance_type", "NON_COMPLIANT")).upper(),
        annotation=raw.get("annotation"),
        region=raw.get("region"),
    )


def _coerce_native_finding(raw: Dict[str, Any]) -> Finding:
    """Build a :class:`Finding` from the native AWS Config evaluation shape."""
    identifier = raw.get("EvaluationResultIdentifier", {})
    qualifier = identifier.get("EvaluationResultQualifier", {})
    return Finding(
        config_rule_name=qualifier.get("ConfigRuleName", "unknown-rule"),
        resource_type=qualifier.get("ResourceType", "AWS::::Account"),
        resource_id=qualifier.get("ResourceId", "unknown"),
        compliance_type=str(raw.get("ComplianceType", "NON_COMPLIANT")).upper(),
        annotation=raw.get("Annotation"),
    )


def _extract_finding_list(doc: Union[Dict[str, Any], List[Any]]) -> List[Dict[str, Any]]:
    """Locate the list of raw finding dicts within a parsed document."""
    if isinstance(doc, list):
        return [item for item in doc if isinstance(item, dict)]
    if isinstance(doc, dict):
        for key in ("findings", "EvaluationResults", "ComplianceByResources"):
            value = doc.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    raise ParseError(
        "Could not find a findings list. Expected a 'findings' key, an "
        "'EvaluationResults' key, or a top-level JSON array."
    )


def parse_findings(doc: Union[Dict[str, Any], List[Any]], source: str = "dict") -> FindingSet:
    """Parse an already-loaded JSON document into a :class:`FindingSet`."""
    raw_findings = _extract_finding_list(doc)
    findings = [_coerce_finding(item) for item in raw_findings]

    account_id = "000000000000"
    region = "us-east-1"
    if isinstance(doc, dict):
        account_id = str(doc.get("account_id", account_id))
        region = str(doc.get("region", region))

    return FindingSet(
        findings=findings,
        account_id=account_id,
        region=region,
        source=source,
    )


def load_findings(path: Union[str, Path]) -> FindingSet:
    """Load and parse AWS Config findings from a JSON file path."""
    p = Path(path)
    if not p.exists():
        raise ParseError(f"Input file not found: {p}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ParseError(f"{p} is not valid JSON: {exc}") from exc
    return parse_findings(doc, source=p.name)
