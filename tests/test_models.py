import dataclasses
import json

import pytest

from explainer.models import AbstractionResult, ExplanationObject, NormalisedFinding, TreeOutcome


def _empty_finding(**overrides) -> NormalisedFinding:
    fields = {
        "vulnerability_id": "CVE-2024-0001",
        "additional_cve_ids": [],
        "title": "Example",
        "severity": None,
        "severity_band": None,
        "cvss_score": None,
        "exploit_available": None,
        "known_exploited": None,
        "attack_vector": None,
        "patch_available": None,
        "patch_age_days": None,
        "days_open": None,
        "threshold_days": None,
        "solution_text": None,
        "asset_id": None,
        "hostname": None,
        "operating_system": None,
        "asset_environment": None,
        "asset_criticality": None,
        "asset_internet_facing": None,
        "status": None,
        "last_scan_date": None,
        "source_format": "qualys_json",
        "absent_by_format": frozenset(),
    }
    fields.update(overrides)
    return NormalisedFinding(**fields)


def test_normalised_finding_fields_are_accessible():
    finding = _empty_finding()

    assert finding.vulnerability_id == "CVE-2024-0001"
    assert finding.source_format == "qualys_json"


def test_normalised_finding_is_immutable():
    finding = _empty_finding()

    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.vulnerability_id = "CVE-2024-0002"


def test_tree_outcome_and_abstraction_result_construction():
    outcome = TreeOutcome(value="High", path=["step one"], inputs_used={"exploit_available": True})
    result = AbstractionResult(
        exploitation_likelihood=outcome,
        business_impact=outcome,
        urgency=outcome,
    )

    assert result.urgency.value == "High"
    assert result.urgency.path == ["step one"]


def test_explanation_object_round_trips_through_asdict_and_json():
    obj = ExplanationObject(
        vulnerability_id="CVE-2024-0001",
        risk_summary="This vulnerability carries Immediate urgency because of X.",
        certainty_level="Known",
        top_factors=[{"label": "X", "field": "exploit_available", "value": True}],
        business_consequence="Could disrupt production.",
        urgency="Immediate",
        time_horizon="Action should begin within the current working week.",
        action="Apply the available security update.",
        mitigation=None,
        evidence_pointers={"exploitation_likelihood": {"inputs": {}, "path": []}},
        limitations=None,
        title="Example finding",
        technical_detail={"cvss_score": 9.8},
    )

    as_dict = dataclasses.asdict(obj)
    round_tripped = json.loads(json.dumps(as_dict))

    assert round_tripped["vulnerability_id"] == "CVE-2024-0001"
    assert round_tripped["top_factors"][0]["field"] == "exploit_available"
    assert round_tripped["technical_detail"]["cvss_score"] == 9.8
