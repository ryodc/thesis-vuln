import json
from pathlib import Path

from explainer.ingestion import ISD_ABSENT_FIELDS, ISDCsvParser

ISD_DIR = Path(__file__).resolve().parent.parent / "data" / "isd"


def _load_scenario(name: str) -> dict:
    with open(ISD_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def test_terrapin_scenario_parses_to_expected_finding():
    finding = ISDCsvParser().parse([_load_scenario("scenario_a_terrapin.json")])[0]

    assert finding.vulnerability_id == "CVE-2023-48795"
    assert finding.title == "SSH Prefix Truncation Vulnerability (Terrapin)"
    assert finding.severity_band == "High"
    assert finding.cvss_score is None
    assert finding.exploit_available is None
    assert finding.patch_available is True
    assert finding.days_open == 893
    assert finding.threshold_days == 90
    assert finding.asset_environment == "production"
    assert finding.asset_criticality == "High"
    assert finding.asset_internet_facing is True
    assert finding.source_format == "isd_csv"
    assert finding.absent_by_format == ISD_ABSENT_FIELDS
    assert "Terrapin Vulnerability" in finding.solution_text
    assert "<A HREF" not in finding.solution_text


def test_python_eol_scenario_has_no_cve_id():
    finding = ISDCsvParser().parse([_load_scenario("scenario_c_python_eol.json")])[0]

    assert finding.vulnerability_id is None
    assert finding.title == "EOL/Obsolete Software: Python 3.7.x Detected"
    assert finding.patch_available is False


def test_non_internal_rows_are_filtered_out():
    rows = [
        {"Issue Category": "Out of Compliance Servers", "Issue Title": "Irrelevant"},
        _load_scenario("scenario_a_terrapin.json"),
    ]
    findings = ISDCsvParser().parse(rows)

    assert len(findings) == 1
    assert findings[0].vulnerability_id == "CVE-2023-48795"


def test_html_stripped_from_solution():
    row = dict(_load_scenario("scenario_a_terrapin.json"))
    row["Solution"] = 'See the &quot;vendor&quot; advisory <A HREF="https://example.com">here</A>.'
    finding = ISDCsvParser().parse([row])[0]

    assert finding.solution_text == 'See the "vendor" advisory here.'
