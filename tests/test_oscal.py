"""Tests for the OSCAL 1.1.2 Assessment Results exporter."""

from __future__ import annotations

import json

from fedramp_control_validator.oscal import to_oscal
from fedramp_control_validator.parsers import load_findings
from fedramp_control_validator.validator import validate


def test_oscal_top_level_structure(mixed_finding_set):
    doc = to_oscal(validate(mixed_finding_set))
    assert "assessment-results" in doc
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    assert "uuid" in ar
    assert "import-ap" in ar
    assert len(ar["results"]) == 1


def test_oscal_findings_and_observations(mixed_finding_set):
    ar = to_oscal(validate(mixed_finding_set))["assessment-results"]
    result = ar["results"][0]

    # Every assessed control yields a finding with a satisfied/not-satisfied target.
    states = {f["target"]["status"]["state"] for f in result["findings"]}
    assert states <= {"satisfied", "not-satisfied"}
    assert "not-satisfied" in states  # SC-7 fails

    # Observations exist for non-compliant resources.
    assert result["observations"]
    assert all("collected" in o for o in result["observations"])


def test_oscal_control_ids_are_lowercase(mixed_finding_set):
    ar = to_oscal(validate(mixed_finding_set))["assessment-results"]
    selections = ar["results"][0]["reviewed-controls"]["control-selections"][0]
    ids = [c["control-id"] for c in selections["include-controls"]]
    assert all(cid == cid.lower() for cid in ids)
    assert "sc-7" in ids


def test_oscal_is_deterministic(mixed_finding_set):
    a = to_oscal(validate(mixed_finding_set))
    b = to_oscal(validate(mixed_finding_set))
    # UUIDs are derived deterministically so the documents match except for
    # the wall-clock timestamps.
    a["assessment-results"]["metadata"]["last-modified"] = "X"
    b["assessment-results"]["metadata"]["last-modified"] = "X"
    for doc in (a, b):
        r = doc["assessment-results"]["results"][0]
        r["start"] = r["end"] = "X"
        for obs in r.get("observations", []):
            obs["collected"] = "X"
    assert a["assessment-results"]["uuid"] == b["assessment-results"]["uuid"]
    assert a == b


def test_oscal_serialises_to_json(sample_path):
    doc = to_oscal(validate(load_findings(sample_path)))
    text = json.dumps(doc)  # must be JSON-serialisable
    assert "assessment-results" in text


def test_oscal_props_carry_score(sample_path):
    ar = to_oscal(validate(load_findings(sample_path)))["assessment-results"]
    props = {p["name"]: p["value"] for p in ar["results"][0]["props"]}
    assert "overall-score" in props
    assert "controls-failing" in props
