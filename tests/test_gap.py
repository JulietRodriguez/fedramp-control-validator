"""Tests for the gap analysis."""

from __future__ import annotations

from fedramp_control_validator.gap import build_gaps, gap_summary
from fedramp_control_validator.models import FAIL, PARTIAL
from fedramp_control_validator.parsers import load_findings
from fedramp_control_validator.validator import validate


def test_gaps_only_contain_fail_and_partial(mixed_finding_set):
    report = validate(mixed_finding_set)
    gaps = build_gaps(report)
    statuses = {g.status for g in gaps}
    assert statuses <= {FAIL, PARTIAL}
    # SC-7 (fail) and the two partials should be present
    ids = {g.control_id for g in gaps}
    assert "SC-7" in ids
    assert "SC-28" in ids


def test_gaps_sorted_fail_before_partial(mixed_finding_set):
    report = validate(mixed_finding_set)
    gaps = build_gaps(report)
    seen_partial = False
    for g in gaps:
        if g.status == PARTIAL:
            seen_partial = True
        if g.status == FAIL:
            assert not seen_partial, "a FAIL appeared after a PARTIAL"


def test_gap_reasons_include_annotations(mixed_finding_set):
    report = validate(mixed_finding_set)
    gaps = {g.control_id: g for g in build_gaps(report)}
    sc28 = gaps["SC-28"]
    assert any("No default encryption" in r for r in sc28.reasons)


def test_gap_severity():
    from fedramp_control_validator.gap import Gap

    assert Gap("SC-7", "x", "SC", FAIL, 1, 1, []).severity == "high"
    assert Gap("SC-28", "x", "SC", PARTIAL, 1, 2, []).severity == "medium"


def test_clean_environment_has_no_gaps(examples_dir):
    report = validate(load_findings(examples_dir / "aws_config_findings_clean.json"))
    assert build_gaps(report) == []


def test_gap_summary_shape(sample_path):
    report = validate(load_findings(sample_path))
    summary = gap_summary(report)
    assert summary["account_id"] == "123456789012"
    assert 0 <= summary["overall_score"] <= 100
    assert isinstance(summary["families"], list)
    assert isinstance(summary["gaps"], list)
    assert summary["gaps"], "the demo sample should surface gaps"
    first = summary["gaps"][0]
    assert {"control_id", "status", "severity", "reasons", "rules"} <= set(first)
