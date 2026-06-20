import itertools

import pytest

from explainer.abstraction import (
    assess_exploitation_likelihood,
    assess_preliminary_impact,
    assess_urgency,
    evaluate,
)
from explainer.models import TreeOutcome
from tests.factories import make_finding

# ---------------------------------------------------------------------------
# Tree 1: exploitation likelihood (thesis Table 5.3)
# ---------------------------------------------------------------------------

EXPLOITATION_LIKELIHOOD_CASES = [
    pytest.param({"exploit_available": None}, "Unknown", {"exploit_available"}, id="exploit-unknown"),
    pytest.param(
        {"exploit_available": True, "known_exploited": True},
        "High",
        {"exploit_available", "known_exploited"},
        id="public-exploit-and-known-exploited",
    ),
    pytest.param(
        {"exploit_available": True, "known_exploited": False, "asset_internet_facing": True},
        "High",
        {"exploit_available", "known_exploited", "asset_internet_facing"},
        id="public-exploit-and-internet-facing",
    ),
    pytest.param(
        {"exploit_available": True, "known_exploited": False, "asset_internet_facing": False},
        "Medium",
        {"exploit_available", "known_exploited", "asset_internet_facing"},
        id="public-exploit-not-internet-facing",
    ),
    pytest.param(
        {"exploit_available": False, "known_exploited": True},
        "Medium",
        {"exploit_available", "known_exploited"},
        id="no-public-exploit-but-known-exploited",
    ),
    pytest.param(
        {"exploit_available": False, "known_exploited": False},
        "Low",
        {"exploit_available", "known_exploited"},
        id="no-exploit-no-known-exploitation",
    ),
]


@pytest.mark.parametrize("overrides, expected_value, expected_input_fields", EXPLOITATION_LIKELIHOOD_CASES)
def test_exploitation_likelihood_tree(overrides, expected_value, expected_input_fields):
    finding = make_finding(**overrides)
    outcome = assess_exploitation_likelihood(finding)

    assert outcome.value == expected_value
    assert outcome.path
    assert set(outcome.inputs_used.keys()) == expected_input_fields


# ---------------------------------------------------------------------------
# Tree 2: preliminary impact (environment × technical severity, ADR-0007)
# ---------------------------------------------------------------------------

PRELIMINARY_IMPACT_CASES = [
    pytest.param({"asset_environment": "production", "cvss_score": 9.8}, "High", id="prod-high"),
    pytest.param({"asset_environment": "production", "cvss_score": 5.0}, "Medium", id="prod-moderate"),
    pytest.param({"asset_environment": "production", "cvss_score": 2.0}, "Low", id="prod-low"),
    pytest.param({"asset_environment": "development", "cvss_score": 9.8}, "Medium", id="nonprod-high"),
    pytest.param({"asset_environment": "development", "cvss_score": 5.0}, "Low", id="nonprod-moderate"),
    pytest.param({"asset_environment": "development", "cvss_score": 2.0}, "Low", id="nonprod-low"),
]


@pytest.mark.parametrize("overrides, expected_value", PRELIMINARY_IMPACT_CASES)
def test_preliminary_impact_rule(overrides, expected_value):
    finding = make_finding(**overrides)
    outcome = assess_preliminary_impact(finding)

    assert outcome.value == expected_value
    assert outcome.path
    assert outcome.inputs_used["asset_environment"] == overrides["asset_environment"]


def test_preliminary_impact_uses_severity_band_when_cvss_missing():
    finding = make_finding(asset_environment="production", cvss_score=None, severity_band="High")
    outcome = assess_preliminary_impact(finding)

    assert outcome.value == "High"
    assert outcome.inputs_used == {"asset_environment": "production", "technical_severity": "High"}


def test_preliminary_impact_unknown_when_no_severity():
    finding = make_finding(asset_environment="production", cvss_score=None, severity_band=None)
    outcome = assess_preliminary_impact(finding)

    assert outcome.value == "Unknown"


def test_preliminary_impact_unknown_when_environment_missing():
    finding = make_finding(asset_environment=None, cvss_score=9.8)
    outcome = assess_preliminary_impact(finding)

    assert outcome.value == "Unknown"


# ---------------------------------------------------------------------------
# Tree 3: urgency (thesis Table 5.5, with the Unknown branch from ADR-0004)
# ---------------------------------------------------------------------------


def _likelihood(value: str) -> TreeOutcome:
    return TreeOutcome(value=value, path=["test fixture"], inputs_used={})


def test_urgency_high_likelihood_is_always_immediate():
    finding = make_finding(patch_available=False, days_open=1, threshold_days=90)
    outcome = assess_urgency(finding, _likelihood("High"))

    assert outcome.value == "Immediate"
    assert outcome.inputs_used == {"exploitation_likelihood": "High"}


def test_urgency_medium_likelihood_overdue_with_patch_is_immediate():
    finding = make_finding(patch_available=True, days_open=100, threshold_days=90)
    outcome = assess_urgency(finding, _likelihood("Medium"))

    assert outcome.value == "Immediate"
    assert outcome.inputs_used["days_open"] == 100
    assert outcome.inputs_used["threshold_days"] == 90


def test_urgency_medium_likelihood_not_overdue_is_scheduled():
    finding = make_finding(patch_available=True, days_open=50, threshold_days=90)
    outcome = assess_urgency(finding, _likelihood("Medium"))

    assert outcome.value == "Scheduled"


def test_urgency_medium_likelihood_no_patch_is_scheduled():
    finding = make_finding(patch_available=False, days_open=100, threshold_days=90)
    outcome = assess_urgency(finding, _likelihood("Medium"))

    assert outcome.value == "Scheduled"


def test_urgency_low_likelihood_overdue_with_patch_is_scheduled():
    finding = make_finding(patch_available=True, days_open=100, threshold_days=90)
    outcome = assess_urgency(finding, _likelihood("Low"))

    assert outcome.value == "Scheduled"


def test_urgency_low_likelihood_not_overdue_is_monitor():
    finding = make_finding(patch_available=True, days_open=50, threshold_days=90)
    outcome = assess_urgency(finding, _likelihood("Low"))

    assert outcome.value == "Monitor"


def test_urgency_low_likelihood_no_patch_no_overdue_is_monitor():
    finding = make_finding(patch_available=False, days_open=50, threshold_days=90)
    outcome = assess_urgency(finding, _likelihood("Low"))

    assert outcome.value == "Monitor"


def test_urgency_unknown_likelihood_internet_facing_and_overdue_is_immediate():
    finding = make_finding(asset_internet_facing=True, days_open=893, threshold_days=90)
    outcome = assess_urgency(finding, _likelihood("Unknown"))

    assert outcome.value == "Immediate"
    assert outcome.inputs_used["asset_internet_facing"] is True
    assert outcome.inputs_used["days_open"] == 893
    assert outcome.inputs_used["threshold_days"] == 90
    assert "803" in outcome.path[1]


def test_urgency_unknown_likelihood_overdue_not_exposed_is_scheduled():
    finding = make_finding(asset_internet_facing=False, days_open=100, threshold_days=90)
    outcome = assess_urgency(finding, _likelihood("Unknown"))

    assert outcome.value == "Scheduled"


def test_urgency_unknown_likelihood_within_threshold_with_patch_is_scheduled():
    finding = make_finding(
        asset_internet_facing=False, days_open=30, threshold_days=90, patch_available=True
    )
    outcome = assess_urgency(finding, _likelihood("Unknown"))

    assert outcome.value == "Scheduled"


def test_urgency_unknown_likelihood_within_threshold_no_patch_is_monitor():
    finding = make_finding(
        asset_internet_facing=False, days_open=30, threshold_days=90, patch_available=False
    )
    outcome = assess_urgency(finding, _likelihood("Unknown"))

    assert outcome.value == "Monitor"


def test_urgency_uses_default_threshold_when_not_provided():
    finding = make_finding(asset_internet_facing=True, days_open=967, threshold_days=None)
    outcome = assess_urgency(finding, _likelihood("Unknown"))

    assert outcome.value == "Immediate"
    assert outcome.inputs_used["threshold_days"] == 90


# ---------------------------------------------------------------------------
# Totality: the trees never raise and always return an enumerated value
# ---------------------------------------------------------------------------

VALID_LIKELIHOOD_VALUES = {"High", "Medium", "Low", "Unknown"}
VALID_IMPACT_VALUES = {"High", "Medium", "Low", "Unknown"}
VALID_URGENCY_VALUES = {"Immediate", "Scheduled", "Monitor"}


def test_trees_are_total_over_the_input_space():
    exploit_available_values = [None, True, False]
    known_exploited_values = [None, True, False]
    internet_facing_values = [None, True, False]
    cvss_values = [None, 9.5, 8.0, 5.0, 2.0]
    severity_band_values = [None, "Critical", "High", "Medium", "Low"]
    criticality_values = [None, "High", "Medium", "Low"]
    patch_available_values = [None, True, False]
    days_open_values = [None, 0, 50, 100]
    threshold_values = [None, 90]

    combinations = itertools.product(
        exploit_available_values,
        known_exploited_values,
        internet_facing_values,
        cvss_values,
        severity_band_values,
        criticality_values,
        patch_available_values,
        days_open_values,
        threshold_values,
    )

    for (
        exploit_available,
        known_exploited,
        internet_facing,
        cvss_score,
        severity_band,
        asset_criticality,
        patch_available,
        days_open,
        threshold_days,
    ) in combinations:
        finding = make_finding(
            exploit_available=exploit_available,
            known_exploited=known_exploited,
            asset_internet_facing=internet_facing,
            cvss_score=cvss_score,
            severity_band=severity_band,
            asset_criticality=asset_criticality,
            patch_available=patch_available,
            days_open=days_open,
            threshold_days=threshold_days,
        )

        result = evaluate(finding)

        assert result.exploitation_likelihood.value in VALID_LIKELIHOOD_VALUES
        assert result.business_impact.value in VALID_IMPACT_VALUES
        assert result.urgency.value in VALID_URGENCY_VALUES
        assert result.exploitation_likelihood.path
        assert result.business_impact.path
        assert result.urgency.path
