import json
from pathlib import Path

from explainer.ingestion import QualysJsonParser

SYNTHETIC_DIR = Path(__file__).resolve().parent.parent / "data" / "synthetic"


def _load(name: str) -> dict:
    with open(SYNTHETIC_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def test_scenario_a_parses_with_derivations():
    findings = QualysJsonParser().parse(_load("scenario_a.json"))

    assert len(findings) == 1
    finding = findings[0]

    assert finding.vulnerability_id == "CVE-2024-3094"
    assert finding.additional_cve_ids == []
    assert finding.severity == 5
    assert finding.cvss_score == 9.8
    assert finding.severity_band == "Critical"
    assert finding.exploit_available is True
    assert finding.known_exploited is True
    assert finding.attack_vector == "NETWORK"
    assert finding.patch_available is True
    assert finding.patch_age_days == 12
    assert finding.days_open == 12
    assert finding.threshold_days is None
    assert finding.asset_id == "asset-edge-01"
    assert finding.hostname == "edge-gateway-01"
    assert finding.operating_system == "debian 12"
    assert finding.asset_environment == "production"
    assert finding.asset_criticality == "High"
    assert finding.asset_internet_facing is True
    assert finding.status == "Active"
    assert finding.last_scan_date == "2024-04-10"
    assert finding.source_format == "qualys_json"
    assert finding.absent_by_format == frozenset()


def test_scenario_b_parses_with_derivations():
    finding = QualysJsonParser().parse(_load("scenario_b.json"))[0]

    assert finding.vulnerability_id == "CVE-2024-5021"
    assert finding.cvss_score == 8.5
    assert finding.severity_band == "High"
    assert finding.exploit_available is False
    assert finding.known_exploited is False
    assert finding.patch_age_days == 19
    assert finding.days_open == 95
    assert finding.asset_environment == "development"
    assert finding.asset_criticality == "Low"
    assert finding.asset_internet_facing is False


def test_scenario_c_parses_with_missing_patch_release_date():
    finding = QualysJsonParser().parse(_load("scenario_c.json"))[0]

    assert finding.vulnerability_id == "CVE-2024-8112"
    assert finding.cvss_score == 9.1
    assert finding.severity_band == "Critical"
    assert finding.exploit_available is True
    assert finding.known_exploited is False
    assert finding.patch_available is False
    # patch_release_date is null in the source, so the derivation
    # cannot run and the field is None, not a fabricated value.
    assert finding.patch_age_days is None
    assert finding.days_open == 40
    assert finding.asset_criticality == "Low"
    assert finding.asset_internet_facing is False
    assert finding.solution_text is None
