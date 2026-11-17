"""Tests for the catalog and rule mapping integrity."""

from __future__ import annotations

from fedramp_control_validator import catalog


def test_every_mapped_control_is_in_catalog():
    """No Config rule should map to a control we cannot title."""
    for rule, controls in catalog.RULE_CONTROL_MAP.items():
        for control in controls:
            assert control in catalog.CONTROL_CATALOG, f"{rule} -> unknown control {control}"


def test_every_control_family_is_known():
    for control_id in catalog.CONTROL_CATALOG:
        family = catalog.family_of(control_id)
        assert family in catalog.CONTROL_FAMILIES, f"{control_id} -> unknown family {family}"


def test_control_rule_index_inverts_map():
    index = catalog.control_rule_index()
    # s3 encryption rule contributes to SC-13 and SC-28
    assert "s3-bucket-server-side-encryption-enabled" in index["SC-13"]
    assert "s3-bucket-server-side-encryption-enabled" in index["SC-28"]


def test_families_in_scope_subset_of_families():
    for family in catalog.families_in_scope():
        assert family in catalog.CONTROL_FAMILIES


def test_control_title_fallback():
    assert catalog.control_title("AC-2") == "Account Management"
    assert catalog.control_title("ZZ-99") == "ZZ-99"


def test_user_required_families_present():
    for family in ("AC", "AU", "CM", "IA", "SC", "SI"):
        assert family in catalog.families_in_scope()


def test_scope_numbers_quoted_in_readme():
    """The README states these numbers; keep them true."""
    from fedramp_control_validator.catalog import CONTROL_CATALOG, RULE_CONTROL_MAP

    families = {cid.split("-")[0] for cid in CONTROL_CATALOG}
    mapped = {c for controls in RULE_CONTROL_MAP.values() for c in controls}
    assert len(CONTROL_CATALOG) == 33
    assert len(families) == 10
    assert len(RULE_CONTROL_MAP) == 60
    assert len(mapped) == 31
    assert set(CONTROL_CATALOG) - mapped == {"AC-17", "CM-3"}
