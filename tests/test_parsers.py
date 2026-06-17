"""Tests for the AWS Config findings parsers."""

from __future__ import annotations

import json

import pytest

from fedramp_control_validator.parsers import ParseError, load_findings, parse_findings


def test_load_simplified_sample(sample_path):
    fs = load_findings(sample_path)
    assert fs.account_id == "123456789012"
    assert fs.region == "us-east-1"
    assert fs.source == "aws_config_findings.json"
    assert len(fs) > 30
    assert any(f.is_non_compliant for f in fs.findings)
    assert any(f.is_compliant for f in fs.findings)


def test_load_native_shape(examples_dir):
    fs = load_findings(examples_dir / "aws_config_findings_native.json")
    assert fs.account_id == "210987654321"
    rules = {f.config_rule_name for f in fs.findings}
    assert "s3-bucket-server-side-encryption-enabled" in rules
    # native qualifier fields are mapped through
    s3 = next(f for f in fs.findings if f.config_rule_name == "s3-bucket-server-side-encryption-enabled")
    assert s3.resource_id == "gov-data-lake"
    assert s3.resource_type == "AWS::S3::Bucket"
    assert s3.is_non_compliant


def test_parse_bare_list():
    fs = parse_findings(
        [
            {"config_rule_name": "cloudtrail-enabled", "compliance_type": "COMPLIANT"},
        ]
    )
    assert len(fs) == 1
    assert fs.findings[0].is_compliant


def test_compliance_type_is_uppercased():
    fs = parse_findings({"findings": [{"config_rule_name": "x", "compliance_type": "compliant"}]})
    assert fs.findings[0].compliance_type == "COMPLIANT"
    assert fs.findings[0].is_compliant


def test_missing_file_raises():
    with pytest.raises(ParseError):
        load_findings("does-not-exist.json")


def test_bad_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ParseError):
        load_findings(p)


def test_no_findings_list_raises():
    with pytest.raises(ParseError):
        parse_findings({"account_id": "1", "nope": []})


def test_all_examples_are_valid_json(examples_dir):
    for path in examples_dir.glob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))
