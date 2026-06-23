"""Tests for the CMDB enrichment join step.

Uses the synthetic ISD CSV (three rows) and the existing CMDB and identity
CSVs in data/enrichment/. The CMDB asset (1234abcdefgh5678) is marked
internal and business-critical, so enrichment:
  - overrides the Remote Discovery proxy (Yes -> False, because CMDB says internal)
  - confirms asset_criticality as High (because asset_is_business_critical=TRUE)
"""

import csv
from pathlib import Path

from explainer import abstraction
from explainer.enrichment import enrich, load_asset_lookup, load_identity_lookup
from explainer.ingestion import PARSERS

DATA = Path(__file__).resolve().parent.parent / "data" / "enrichment"
ISD_CSV = DATA / "isd_synthetic.csv"
CMDB_CSV = DATA / "cmdb_asset.csv"
IDENTITY_CSV = DATA / "cmdb_identity.csv"


def _parse_synthetic_isd() -> list:
    with open(ISD_CSV, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    return PARSERS["isd_csv"].parse(rows)


def _findings_by_asset_id(findings: list) -> dict:
    return {f.asset_id: f for f in findings}


# ---------------------------------------------------------------------------
# Exposure correction
# ---------------------------------------------------------------------------


def test_cmdb_overrides_remote_discovery_proxy():
    """Row A: Remote Discovery = Yes but CMDB says internal — internet-facing corrected to False."""
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id == "1234abcdefgh5678")

    assert finding.asset_internet_facing is True  # Remote Discovery = Yes

    asset_lookup = load_asset_lookup(CMDB_CSV)
    enriched = enrich(finding, asset_lookup)

    assert enriched.asset_internet_facing is False  # CMDB: internal, not on external DNS


def test_cmdb_confirms_business_criticality():
    """Row A: CMDB asset_is_business_critical=TRUE -> asset_criticality stays High."""
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id == "1234abcdefgh5678")

    asset_lookup = load_asset_lookup(CMDB_CSV)
    enriched = enrich(finding, asset_lookup)

    assert enriched.asset_criticality == "High"


def test_urgency_changes_after_enrichment():
    """Row A: before enrichment Immediate (internet-facing + overdue); after Scheduled."""
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id == "1234abcdefgh5678")

    asset_lookup = load_asset_lookup(CMDB_CSV)
    enriched = enrich(finding, asset_lookup)

    before = abstraction.evaluate(finding)
    after = abstraction.evaluate(enriched)

    assert before.urgency.value == "Immediate"  # internet-facing + overdue (200 > 90)
    assert after.urgency.value == "Scheduled"   # not internet-facing, but still overdue


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


def test_graceful_degradation_empty_asset_id():
    """Row B: empty Asset Id -> finding returned unchanged (same object)."""
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id is None and f.vulnerability_id == "CVE-2024-31497")

    assert finding.asset_id is None

    asset_lookup = load_asset_lookup(CMDB_CSV)
    enriched = enrich(finding, asset_lookup)

    assert enriched is finding


def test_graceful_degradation_unmatched_asset_id():
    """Row C: asset_id not present in CMDB -> finding returned unchanged (same object)."""
    findings = _parse_synthetic_isd()
    finding = next(f for f in findings if f.asset_id == "AST-NOTFOUND")

    asset_lookup = load_asset_lookup(CMDB_CSV)
    enriched = enrich(finding, asset_lookup)

    assert enriched is finding


# ---------------------------------------------------------------------------
# Identity join (demonstrated lookup, not wired into finding)
# ---------------------------------------------------------------------------


def test_identity_lookup_resolves_asset_owner():
    """AST owner resolves in the identity lookup and is a privileged account."""
    asset_lookup = load_asset_lookup(CMDB_CSV)
    identity_lookup = load_identity_lookup(IDENTITY_CSV)

    asset = asset_lookup.get("1234abcdefgh5678")
    assert asset is not None

    owner_email = asset["asset_owner"].strip().lower()
    identity = identity_lookup.get(owner_email)

    assert identity is not None
    assert identity["identity_is_privileged"].strip().lower() in {"true", "yes", "1"}
