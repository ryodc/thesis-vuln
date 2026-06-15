import csv
import json
from pathlib import Path

from explainer.ingestion import ISD_ABSENT_FIELDS, ISDCsvParser

ISD_DIR = Path(__file__).resolve().parent.parent / "data" / "isd"


def _load_scenario(name: str) -> dict:
    with open(ISD_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def test_terrapin_scenario_parses_to_expected_finding():
    row = _load_scenario("scenario_a_terrapin.json")
    finding = ISDCsvParser().parse([row])[0]

    assert finding.vulnerability_id == "CVE-2023-48795"
    assert finding.additional_cve_ids == []
    assert finding.title == "SSH Prefix Truncation Vulnerability (Terrapin)"
    assert finding.severity_band == "High"
    assert finding.cvss_score is None
    assert finding.exploit_available is None
    assert finding.known_exploited is None
    assert finding.patch_available is True
    assert finding.patch_age_days is None
    assert finding.days_open == 893
    assert finding.threshold_days == 90
    assert finding.operating_system == "ubuntu 18.04"
    assert finding.asset_environment == "production"
    assert finding.asset_criticality == "High"
    assert finding.asset_internet_facing is True
    assert finding.status == "Reopened"
    assert finding.last_scan_date == "2026-06-06"
    assert finding.source_format == "isd_csv"
    assert finding.absent_by_format == ISD_ABSENT_FIELDS
    assert "Terrapin Vulnerability" in finding.solution_text
    assert "<A HREF" not in finding.solution_text
    assert "<P>" not in finding.solution_text


def test_putty_scenario_parses_with_internal_asset():
    row = _load_scenario("scenario_b_putty.json")
    finding = ISDCsvParser().parse([row])[0]

    assert finding.vulnerability_id == "CVE-2024-31497"
    assert finding.days_open == 30
    assert finding.threshold_days == 90
    assert finding.patch_available is True
    assert finding.asset_internet_facing is False
    assert finding.status == "Active"


def test_python_eol_scenario_has_no_cve_id():
    row = _load_scenario("scenario_c_python_eol.json")
    finding = ISDCsvParser().parse([row])[0]

    assert finding.vulnerability_id is None
    assert finding.additional_cve_ids == []
    assert finding.title == "EOL/Obsolete Software: Python 3.7.x Detected"
    assert finding.patch_available is False
    assert finding.days_open == 967
    assert finding.solution_text == (
        "Customers are advised to upgrade to the latest supported python "
        "releases to remediate this vulnerability. For latest release visit here."
    )


def test_non_internal_rows_are_filtered_out():
    rows = [
        {"Issue Category": "Out of Compliance Servers", "Issue Title": "Irrelevant"},
        _load_scenario("scenario_a_terrapin.json"),
    ]

    findings = ISDCsvParser().parse(rows)

    assert len(findings) == 1
    assert findings[0].vulnerability_id == "CVE-2023-48795"


def test_multi_cve_row_splits_into_primary_and_additional_ids():
    row = dict(_load_scenario("scenario_a_terrapin.json"))
    row["CVE ID"] = "CVE-2023-48795, CVE-2023-99999, CVE-2023-11111"

    finding = ISDCsvParser().parse([row])[0]

    assert finding.vulnerability_id == "CVE-2023-48795"
    assert finding.additional_cve_ids == ["CVE-2023-99999", "CVE-2023-11111"]


def test_html_and_escaped_entities_are_stripped_from_solution():
    row = dict(_load_scenario("scenario_a_terrapin.json"))
    row["Solution"] = 'See the &quot;vendor&quot; advisory <A HREF="https://example.com">here</A>.<P>\nApply the patch.'

    finding = ISDCsvParser().parse([row])[0]

    assert finding.solution_text == 'See the "vendor" advisory here. Apply the patch.'


def test_csv_with_bom_is_read_correctly():
    with open(ISD_DIR / "ISD_ISSUES_export_jun_2026.csv", encoding="utf-8-sig", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        first_row = next(reader)

    # If the BOM were not handled, the first column name would be
    # prefixed with a U+FEFF character and this key would not exist.
    assert "Asset Type" in first_row
