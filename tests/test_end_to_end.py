"""Full pipeline end-to-end tests against the frozen golden outputs.

Each golden file in tests/golden/ is the byte-for-byte expected
ExplanationObject for one scenario, reviewed by hand against Section 9
of the master plan. Any change to ingestion, abstraction or explanation
that alters one of these outputs must update the golden file
deliberately - that update is the regression record.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from explainer import abstraction, explanation
from explainer.ingestion import PARSERS

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
GOLDEN_DIR = Path(__file__).resolve().parent / "golden"

SCENARIOS = [
    ("synthetic_a.json", "qualys_json", DATA_DIR / "synthetic" / "scenario_a.json"),
    ("synthetic_b.json", "qualys_json", DATA_DIR / "synthetic" / "scenario_b.json"),
    ("synthetic_c.json", "qualys_json", DATA_DIR / "synthetic" / "scenario_c.json"),
    ("isd_a.json", "isd_csv", DATA_DIR / "isd" / "scenario_a_terrapin.json"),
    ("isd_b.json", "isd_csv", DATA_DIR / "isd" / "scenario_b_putty.json"),
    ("isd_c.json", "isd_csv", DATA_DIR / "isd" / "scenario_c_python_eol.json"),
]


def _run_pipeline(source_format: str, path: Path) -> dict:
    parser = PARSERS[source_format]
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw_records = [raw] if source_format == "isd_csv" else raw
    finding = parser.parse(raw_records)[0]
    result = abstraction.evaluate(finding)
    explanation_object = explanation.build_explanation(finding, result)
    return dataclasses.asdict(explanation_object)


@pytest.mark.parametrize("golden_name, source_format, source_path", SCENARIOS)
def test_pipeline_output_matches_golden(golden_name, source_format, source_path):
    actual = _run_pipeline(source_format, source_path)
    expected = json.loads((GOLDEN_DIR / golden_name).read_text(encoding="utf-8"))

    assert actual == expected
