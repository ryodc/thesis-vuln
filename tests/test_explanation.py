from explainer.abstraction import evaluate
from explainer.explanation import build_explanation, derive_certainty, select_top_factors
from explainer.models import TreeOutcome
from tests.factories import make_finding

ISD_ABSENT_FIELDS = frozenset(
    {"cvss_score", "exploit_available", "known_exploited", "attack_vector", "asset_id", "hostname"}
)


# ---------------------------------------------------------------------------
# Content selection
# ---------------------------------------------------------------------------


def test_top_factors_capped_at_three_and_drawn_from_decisive_paths():
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        cvss_score=None,
        severity_band="High",
        asset_criticality="High",
        asset_environment="production",
        asset_internet_facing=True,
        days_open=893,
        threshold_days=90,
        patch_available=True,
    )
    abstraction = evaluate(finding)

    factors = select_top_factors(finding, abstraction)

    assert len(factors) <= 3
    fields = [factor["field"] for factor in factors]
    assert "days_open" in fields
    assert "asset_internet_facing" in fields
    assert "asset_criticality" in fields


def test_top_factors_exclude_unknown_likelihood_path():
    # exploitation likelihood is Unknown for all ISD findings, so its
    # inputs (just exploit_available=None) must never appear as a factor.
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        severity_band="Low",
        asset_criticality="Low",
        asset_internet_facing=False,
        days_open=10,
        threshold_days=90,
        patch_available=False,
    )
    abstraction = evaluate(finding)

    factors = select_top_factors(finding, abstraction)

    assert all(factor["field"] != "exploit_available" for factor in factors)


def test_top_factors_deduplicate_by_field():
    # asset_internet_facing is read by both the likelihood and urgency
    # trees when likelihood is High; it must only appear once.
    finding = make_finding(
        exploit_available=True,
        known_exploited=True,
        asset_internet_facing=True,
        severity_band="Low",
        asset_criticality="Low",
        patch_available=True,
        days_open=10,
        threshold_days=90,
    )
    abstraction = evaluate(finding)

    factors = select_top_factors(finding, abstraction)

    fields = [factor["field"] for factor in factors]
    assert len(fields) == len(set(fields))


# ---------------------------------------------------------------------------
# Certainty derivation
# ---------------------------------------------------------------------------


def test_certainty_known_when_nothing_missing():
    finding = make_finding(
        exploit_available=True,
        known_exploited=False,
        asset_internet_facing=True,
        cvss_score=9.8,
        asset_criticality="High",
        patch_available=True,
        days_open=10,
        threshold_days=90,
    )
    abstraction = evaluate(finding)

    assert derive_certainty(finding, abstraction) == "Known"


def test_certainty_known_uncertainty_when_missing_fields_are_documented_absent():
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        severity_band="High",
        asset_criticality="High",
        asset_internet_facing=True,
        days_open=893,
        threshold_days=90,
        patch_available=True,
    )
    abstraction = evaluate(finding)

    assert derive_certainty(finding, abstraction) == "Known uncertainty"


def test_certainty_unknowable_when_no_cve_identifier():
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        vulnerability_id=None,
        severity_band="High",
        asset_criticality="High",
        asset_internet_facing=False,
        days_open=967,
        threshold_days=90,
        patch_available=False,
    )
    abstraction = evaluate(finding)

    assert derive_certainty(finding, abstraction) == "Unknowable"


def test_certainty_unknown_uncertainty_when_normally_present_field_is_null():
    # qualys_json declares no absent fields, so a None exploit_available
    # here is an unexpected gap, not a documented one.
    finding = make_finding(
        source_format="qualys_json",
        absent_by_format=frozenset(),
        exploit_available=None,
        cvss_score=9.0,
        asset_criticality="High",
        patch_available=True,
        days_open=10,
        threshold_days=90,
    )
    abstraction = evaluate(finding)

    assert derive_certainty(finding, abstraction) == "Unknown uncertainty"


# ---------------------------------------------------------------------------
# Mitigation population (ADR-0005)
# ---------------------------------------------------------------------------


def test_mitigation_populated_when_urgency_immediate_and_patch_available():
    finding = make_finding(
        exploit_available=True,
        known_exploited=True,
        asset_internet_facing=True,
        cvss_score=9.8,
        asset_criticality="High",
        patch_available=True,
        days_open=5,
        threshold_days=90,
        solution_text="Apply the vendor update.",
    )
    abstraction = evaluate(finding)

    explanation = build_explanation(finding, abstraction)

    assert abstraction.urgency.value == "Immediate"
    assert explanation.mitigation is not None
    assert "validated against this specific system" in explanation.mitigation


def test_mitigation_populated_when_no_patch_available_even_if_not_immediate():
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        vulnerability_id=None,
        severity_band="High",
        asset_criticality="High",
        asset_internet_facing=False,
        days_open=10,
        threshold_days=90,
        patch_available=False,
    )
    abstraction = evaluate(finding)

    explanation = build_explanation(finding, abstraction)

    assert abstraction.urgency.value != "Immediate"
    assert explanation.mitigation is not None
    assert "validated against this specific system" in explanation.mitigation


def test_mitigation_absent_when_not_immediate_and_patch_available():
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        severity_band="High",
        asset_criticality="High",
        asset_internet_facing=False,
        days_open=30,
        threshold_days=90,
        patch_available=True,
    )
    abstraction = evaluate(finding)

    explanation = build_explanation(finding, abstraction)

    assert abstraction.urgency.value == "Scheduled"
    assert explanation.mitigation is None


# ---------------------------------------------------------------------------
# Limitations assembly
# ---------------------------------------------------------------------------


def test_limitations_none_when_nothing_to_report():
    finding = make_finding(
        source_format="qualys_json",
        absent_by_format=frozenset(),
        exploit_available=True,
        known_exploited=True,
        asset_internet_facing=True,
        cvss_score=9.8,
        asset_criticality="High",
        patch_available=True,
        days_open=10,
        threshold_days=90,
    )
    abstraction = evaluate(finding)

    explanation = build_explanation(finding, abstraction)

    assert explanation.limitations is None


def test_limitations_assembled_for_isd_eol_finding():
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        vulnerability_id=None,
        severity_band="High",
        asset_environment="production",
        asset_criticality="High",
        asset_internet_facing=False,
        days_open=967,
        threshold_days=90,
        patch_available=False,
    )
    abstraction = evaluate(finding)

    explanation = build_explanation(finding, abstraction)

    assert "ISD data source" in explanation.limitations
    assert "categorical severity" in explanation.limitations
    assert "production environment label" in explanation.limitations
    assert "No CVE identifier is associated" in explanation.limitations
    assert explanation.limitations.endswith(
        "The system does not determine asset ownership or final remediation decisions."
    )
