"""Tests for the Rich CLI."""

from __future__ import annotations

import json

from fedramp_control_validator.cli import main


def test_no_input_prints_help(capsys):
    assert main([]) == 1
    out = capsys.readouterr().out
    assert "usage" in out.lower()


def test_run_against_sample(sample_path, capsys):
    rc = main([str(sample_path), "--no-banner"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "FedRAMP Moderate Assessment" in out
    assert "Gap Analysis" in out


def test_missing_file_returns_2(capsys):
    assert main(["nope.json"]) == 2
    assert "Error" in capsys.readouterr().out


def test_writes_oscal_and_gap(sample_path, tmp_path):
    oscal_path = tmp_path / "ar.json"
    gap_path = tmp_path / "gap.json"
    rc = main(
        [str(sample_path), "--no-banner", "-o", str(oscal_path), "-g", str(gap_path)]
    )
    assert rc == 0
    ar = json.loads(oscal_path.read_text(encoding="utf-8"))
    assert ar["assessment-results"]["metadata"]["oscal-version"] == "1.1.2"
    gap = json.loads(gap_path.read_text(encoding="utf-8"))
    assert "gaps" in gap


def test_json_flag_emits_oscal(sample_path, capsys):
    rc = main([str(sample_path), "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "assessment-results" in out


def test_fail_under_threshold(sample_path, capsys):
    # The demo sample is well below 100%, so this must fail the gate.
    rc = main([str(sample_path), "--no-banner", "--fail-under", "100"])
    assert rc == 3
    assert "below the required" in capsys.readouterr().out


def test_fail_under_passes_for_clean(examples_dir):
    clean = examples_dir / "aws_config_findings_clean.json"
    assert main([str(clean), "--no-banner", "--fail-under", "100"]) == 0
