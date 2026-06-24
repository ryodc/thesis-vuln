"""Tests for the CMDB join inside ISDCsvParser.

The join happens at ingestion time: when an ISD row's Asset Id resolves in
the CMDB asset table, the CMDB values override the ISD-only proxy signals.
"""

import csv
from pathlib import Path

from explainer import abstraction, explanation
from explainer.ingestion import PARSERS

DATA = Path(__file__).resolve().parent.parent / "data" / "enrichment"
ISD_CSV = DATA / "isd_synthetic.csv"
CMDB_CSV = DATA / "cmdb_asset.csv"
IDENTITY_CSV = DATA / "cmdb_identity.csv"


def _parse_synthetic_isd() -> list:
    with open(ISD_CSV, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    return PARSERS["isd_csv"].parse(rows)


def test_walter_cmdb_corrects_exposure_and_sets_business_critical():
    """Walter: Remote=Yes but CMDB internal → internet_facing=False; business_critical=True."""
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id == "1234abcdefgh5678")

    assert finding.asset_internet_facing is False
    assert finding.asset_business_critical is True


def test_walter_pipeline_gives_critical_impact_and_scheduled_urgency():
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id == "1234abcdefgh5678")
    result = abstraction.evaluate(finding)

    assert result.business_impact.value == "Critical"
    assert result.urgency.value == "Scheduled"


def test_gus_cmdb_corrects_exposure_up_and_raises_impact_to_critical():
    """Gus: Remote=No but CMDB external+on_external_dns → internet_facing=True; Critical impact; Immediate urgency."""
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id == "AST-0003")
    result = abstraction.evaluate(finding)

    assert finding.asset_internet_facing is True
    assert finding.asset_business_critical is True
    assert result.business_impact.value == "Critical"
    assert result.urgency.value == "Immediate"


def test_jesse_not_business_critical_impact_stays_high():
    """Jesse: business_critical=False → complete path but impact stays High (no inflation)."""
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id == "AST-0002")
    result = abstraction.evaluate(finding)

    assert finding.asset_business_critical is False
    assert result.business_impact.value == "High"
    assert "complete impact" in result.business_impact.path[1]


def test_no_cmdb_match_falls_back_to_preliminary_assessment():
    """ISD-004 (empty key) and ISD-005 (unmatched key) stay on the preliminary path."""
    findings = _parse_synthetic_isd()

    empty_key = next(f for f in findings if f.vulnerability_id == "CVE-2024-38476")
    unmatched = next(f for f in findings if f.asset_id == "AST-NOTFOUND")

    assert empty_key.asset_business_critical is None
    assert unmatched.asset_business_critical is None

    for finding in (empty_key, unmatched):
        result = abstraction.evaluate(finding)
        assert result.business_impact.value == "High"
        assert "asset_business_critical" not in result.business_impact.inputs_used


def test_limitation_text_reflects_enrichment_status():
    """Enriched finding gets the asset-inventory sentence; unenriched gets the preliminary one."""
    findings = _parse_synthetic_isd()
    walter = next(f for f in findings if f.asset_id == "1234abcdefgh5678")
    fallback = next(f for f in findings if f.vulnerability_id == "CVE-2024-38476")

    walter_exp = explanation.build_explanation(walter, abstraction.evaluate(walter))
    fallback_exp = explanation.build_explanation(fallback, abstraction.evaluate(fallback))

    assert "asset inventory" in walter_exp.limitations
    assert "preliminary" in fallback_exp.limitations


def test_asset_owner_resolves_in_identity_lookup():
    """Walter and Gus owners are privileged accounts; Jesse's is not."""
    with open(CMDB_CSV, encoding="utf-8-sig", newline="") as f:
        assets = {row["asset_id"].strip(): row for row in csv.DictReader(f) if row.get("asset_id", "").strip()}
    with open(IDENTITY_CSV, encoding="utf-8-sig", newline="") as f:
        identities = {row["identity_email"].strip().lower(): row for row in csv.DictReader(f) if row.get("identity_email", "").strip()}

    def privileged(asset_id: str) -> bool:
        email = assets[asset_id]["asset_owner"].strip().lower()
        return identities[email]["identity_is_privileged"].strip().lower() in {"true", "yes", "1"}

    assert privileged("1234abcdefgh5678") is True   # Walter
    assert privileged("AST-0003") is True             # Gus
    assert privileged("AST-0002") is False            # Jesse
    assert privileged("AST-0004") is True             # Mike


def test_mike_owner_privileged_gives_critical_impact():
    """Mike: business_critical=False but owner is domain admin → owner_privileged=True → Critical."""
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id == "AST-0004")
    result = abstraction.evaluate(finding)

    assert finding.asset_business_critical is False
    assert finding.asset_owner_privileged is True
    assert result.business_impact.value == "Critical"


def test_jesse_vs_mike_owner_privilege_changes_impact():
    """Same credentials (not business-critical, same severity) but owner privilege alone raises Mike to Critical."""
    findings = _parse_synthetic_isd()
    jesse = next(f for f in findings if f.asset_id == "AST-0002")
    mike = next(f for f in findings if f.asset_id == "AST-0004")

    assert jesse.asset_owner_privileged is False
    assert mike.asset_owner_privileged is True
    assert abstraction.evaluate(jesse).business_impact.value == "High"
    assert abstraction.evaluate(mike).business_impact.value == "Critical"


def test_mike_privacy_owner_email_not_on_finding():
    """The owner email must not appear anywhere on the NormalisedFinding — only the boolean flag is stored."""
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id == "AST-0004")

    import dataclasses
    all_values = str(dataclasses.asdict(finding))
    assert "mike_ehrmantraut" not in all_values
