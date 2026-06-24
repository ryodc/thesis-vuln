from explainer.abstraction import evaluate
from explainer.explanation import build_explanation, derive_certainty, select_top_factors
from tests.factories import make_finding

ISD_ABSENT_FIELDS = frozenset(
    {"cvss_score", "exploit_available", "known_exploited", "attack_vector", "asset_id", "hostname"}
)


def test_top_factors_capped_at_three_and_drawn_from_decisive_paths():
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        severity_band="High",
        asset_environment="production",
        asset_internet_facing=True,
        days_open=893,
        threshold_days=90,
        patch_available=True,
    )
    factors = select_top_factors(finding, evaluate(finding))

    assert len(factors) <= 3
    fields = [f["field"] for f in factors]
    assert "days_open" in fields
    assert "asset_internet_facing" in fields


def test_top_factors_exclude_unknown_likelihood_inputs():
    # ISD findings have Unknown exploitation likelihood; its inputs must not
    # surface as factors since they add no information.
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        severity_band="Low",
        asset_internet_facing=False,
        days_open=10,
        threshold_days=90,
    )
    factors = select_top_factors(finding, evaluate(finding))

    assert all(f["field"] != "exploit_available" for f in factors)


def test_certainty_known_when_all_fields_present():
    finding = make_finding(
        exploit_available=True,
        known_exploited=False,
        asset_internet_facing=True,
        cvss_score=9.8,
        asset_environment="production",
        patch_available=True,
        days_open=10,
        threshold_days=90,
    )
    assert derive_certainty(finding, evaluate(finding)) == "Known"


def test_certainty_known_uncertainty_for_isd_findings():
    # ISD structurally cannot provide exploit data; that absence is documented
    # in absent_by_format, so the rating is "Known uncertainty" not "Unknown".
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        severity_band="High",
        asset_environment="production",
        asset_internet_facing=True,
        days_open=893,
        threshold_days=90,
        patch_available=True,
    )
    assert derive_certainty(finding, evaluate(finding)) == "Known uncertainty"


def test_mitigation_populated_when_immediate_urgency():
    finding = make_finding(
        exploit_available=True,
        known_exploited=True,
        cvss_score=9.8,
        patch_available=True,
        days_open=5,
        threshold_days=90,
        solution_text="Apply the vendor update.",
    )
    result = evaluate(finding)
    exp = build_explanation(finding, result)

    assert result.urgency.value == "Immediate"
    assert exp.mitigation is not None


def test_limitations_assembled_for_isd_eol_finding():
    finding = make_finding(
        source_format="isd_csv",
        absent_by_format=ISD_ABSENT_FIELDS,
        vulnerability_id=None,
        severity_band="High",
        asset_environment="production",
        asset_internet_facing=False,
        days_open=967,
        threshold_days=90,
        patch_available=False,
    )
    exp = build_explanation(finding, evaluate(finding))

    assert "ISD data source" in exp.limitations
    assert "preliminary assessment" in exp.limitations
    assert "No CVE identifier" in exp.limitations
