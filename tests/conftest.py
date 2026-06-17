"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from fedramp_control_validator.models import Finding, FindingSet

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def examples_dir() -> Path:
    return EXAMPLES


@pytest.fixture
def sample_path(examples_dir: Path) -> Path:
    return examples_dir / "aws_config_findings.json"


@pytest.fixture
def mixed_finding_set() -> FindingSet:
    """A small hand-built set exercising pass / fail / partial / n-a."""
    return FindingSet(
        account_id="123456789012",
        region="us-east-1",
        source="fixture",
        findings=[
            # SC-13 / SC-28 -> partial (one pass, one fail)
            Finding("s3-bucket-server-side-encryption-enabled", "AWS::S3::Bucket", "ok", "COMPLIANT"),
            Finding(
                "s3-bucket-server-side-encryption-enabled",
                "AWS::S3::Bucket",
                "bad",
                "NON_COMPLIANT",
                annotation="No default encryption.",
            ),
            # SC-7 (restricted-ssh) -> fail (all non-compliant)
            Finding("restricted-ssh", "AWS::EC2::SecurityGroup", "sg-1", "NON_COMPLIANT"),
            # AU-2 (cloudtrail-enabled) -> pass
            Finding("cloudtrail-enabled", "AWS::::Account", "123456789012", "COMPLIANT"),
            # NOT_APPLICABLE should be ignored entirely
            Finding("db-instance-backup-enabled", "AWS::RDS::DBInstance", "n/a", "NOT_APPLICABLE"),
        ],
    )
