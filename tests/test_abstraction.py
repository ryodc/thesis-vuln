from explainer.abstraction import (
    assess_exploitation_likelihood,
    assess_preliminary_impact,
    assess_urgency,
    evaluate,
)
from explainer.models import TreeOutcome
from tests.factories import make_finding


# ---------------------------------------------------------------------------
# Tree 1: exploitation likelihood
# ---------------------------------------------------------------------------


def test_exploitation_likelihood_high_when_public_exploit_and_known_exploited():
    finding = make_finding(exploit_available=True, known_exploited=True)
    assert assess_exploitation_likelihood(finding).value == "High"


def test_exploitation_likelihood_medium_when_exploit_but_not_internet_facing():
    finding = make_finding(exploit_available=True, known_exploited=False, asset_internet_facing=False)
    assert assess_exploitation_likelihood(finding).value == "Medium"


def test_exploitation_likelihood_unknown_when_no_exploit_data():
    finding = make_finding(exploit_available=None)
    assert assess_exploitation_likelihood(finding).value == "Unknown"


# ---------------------------------------------------------------------------
# Tree 2: impact (preliminary when not enriched, complete when enriched)
# ---------------------------------------------------------------------------


def test_preliminary_impact_production_high_severity_gives_high():
    finding = make_finding(asset_environment="production", cvss_score=9.8)
    outcome = assess_preliminary_impact(finding)

    assert outcome.value == "High"
    assert "asset_business_critical" not in outcome.inputs_used


def test_preliminary_impact_nonproduction_high_severity_gives_medium():
    finding = make_finding(asset_environment="development", cvss_score=9.8)
    assert assess_preliminary_impact(finding).value == "Medium"


def test_complete_impact_business_critical_production_reaches_critical():
    finding = make_finding(
        asset_environment="production", cvss_score=9.8, asset_business_critical=True
    )
    outcome = assess_preliminary_impact(finding)

    assert outcome.value == "Critical"
    assert "asset_business_critical" in outcome.inputs_used


def test_complete_impact_not_business_critical_stays_capped_at_high():
    finding = make_finding(
        asset_environment="production", cvss_score=9.8, asset_business_critical=False
    )
    assert assess_preliminary_impact(finding).value == "High"


def test_impact_unknown_when_environment_or_severity_missing():
    assert assess_preliminary_impact(make_finding(asset_environment=None, cvss_score=9.8)).value == "Unknown"
    assert assess_preliminary_impact(make_finding(asset_environment="production", cvss_score=None, severity_band=None)).value == "Unknown"


def test_complete_impact_owner_privileged_only_reaches_critical():
    """Owner privilege alone (not business-critical) is sufficient to reach Critical."""
    finding = make_finding(
        asset_environment="production", cvss_score=9.8,
        asset_business_critical=False, asset_owner_privileged=True,
    )
    outcome = assess_preliminary_impact(finding)

    assert outcome.value == "Critical"
    assert outcome.inputs_used["asset_owner_privileged"] is True


def test_complete_impact_neither_elevated_stays_high():
    """When both flags are False, the result is the standard (non-elevated) matrix → High."""
    finding = make_finding(
        asset_environment="production", cvss_score=9.8,
        asset_business_critical=False, asset_owner_privileged=False,
    )
    assert assess_preliminary_impact(finding).value == "High"


# ---------------------------------------------------------------------------
# Tree 3: urgency
# ---------------------------------------------------------------------------


def _likelihood(value: str) -> TreeOutcome:
    return TreeOutcome(value=value, path=["test fixture"], inputs_used={})


def test_urgency_high_likelihood_is_always_immediate():
    finding = make_finding(patch_available=False, days_open=1, threshold_days=90)
    assert assess_urgency(finding, _likelihood("High")).value == "Immediate"


def test_urgency_unknown_likelihood_internet_facing_and_overdue_is_immediate():
    finding = make_finding(asset_internet_facing=True, days_open=100, threshold_days=90)
    outcome = assess_urgency(finding, _likelihood("Unknown"))

    assert outcome.value == "Immediate"
    assert outcome.inputs_used["asset_internet_facing"] is True


def test_urgency_unknown_likelihood_overdue_not_exposed_is_scheduled():
    finding = make_finding(asset_internet_facing=False, days_open=100, threshold_days=90)
    assert assess_urgency(finding, _likelihood("Unknown")).value == "Scheduled"


def test_urgency_unknown_likelihood_within_threshold_no_patch_is_monitor():
    finding = make_finding(
        asset_internet_facing=False, days_open=30, threshold_days=90, patch_available=False
    )
    assert assess_urgency(finding, _likelihood("Unknown")).value == "Monitor"
