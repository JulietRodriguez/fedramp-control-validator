"""Tests for the scoring engine."""

from __future__ import annotations

from fedramp_control_validator.models import FAIL, NOT_ASSESSED, PARTIAL, PASS
from fedramp_control_validator.parsers import load_findings
from fedramp_control_validator.validator import validate


def _control(report, control_id):
    return next(c for c in report.controls if c.control_id == control_id)


def test_status_classification(mixed_finding_set):
    report = validate(mixed_finding_set)

    assert _control(report, "SC-28").status == PARTIAL
    assert _control(report, "SC-13").status == PARTIAL
    assert _control(report, "SC-7").status == FAIL
    assert _control(report, "AU-2").status == PASS


def test_not_applicable_findings_are_ignored(mixed_finding_set):
    report = validate(mixed_finding_set)
    # db-instance-backup-enabled was NOT_APPLICABLE -> CP-9 stays not-assessed
    assert _control(report, "CP-9").status == NOT_ASSESSED


def test_partial_control_resource_counts(mixed_finding_set):
    report = validate(mixed_finding_set)
    sc28 = _control(report, "SC-28")
    assert sc28.total_resources == 2
    assert sc28.passing_resources == 1
    assert sc28.failing_resources == 1
    assert 0.0 < sc28.score < 1.0


def test_family_rollup(mixed_finding_set):
    report = validate(mixed_finding_set)
    families = {f.family: f for f in report.families}
    # SC has a fail (SC-7) and partials -> partial
    assert families["SC"].status == PARTIAL
    # AU is all pass
    assert families["AU"].status == PASS


def test_every_catalog_control_is_scored(mixed_finding_set):
    from fedramp_control_validator.catalog import CONTROL_CATALOG

    report = validate(mixed_finding_set)
    scored = {c.control_id for c in report.controls}
    assert scored == set(CONTROL_CATALOG)


def test_overall_score_bounds(sample_path):
    report = validate(load_findings(sample_path))
    assert 0.0 <= report.overall_score <= 1.0
    counts = report.counts()
    assert counts[PASS] > 0
    assert counts[FAIL] > 0


def test_clean_environment_all_pass(examples_dir):
    report = validate(load_findings(examples_dir / "aws_config_findings_clean.json"))
    counts = report.counts()
    assert counts[FAIL] == 0
    assert counts[PARTIAL] == 0
    assert counts[PASS] > 0
    assert report.overall_score == 1.0


def test_findings_evaluated_excludes_not_applicable(mixed_finding_set):
    report = validate(mixed_finding_set)
    # 5 findings, one is NOT_APPLICABLE
    assert report.findings_evaluated == 4
