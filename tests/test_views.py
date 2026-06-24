"""Tests for the stakeholder view renderers.

Both renderers consume the same ExplanationObject. The technical view
must surface the evidence; the non-technical view must not leak raw field
names or tree internals.
"""

from __future__ import annotations

import json
from pathlib import Path

from explainer import abstraction, explanation
from explainer.ingestion import PARSERS
from explainer.views import RENDERERS, render_nontechnical, render_technical

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _build_explanation(source_format: str, path: Path):
    parser = PARSERS[source_format]
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw_records = [raw] if source_format == "isd_csv" else raw
    finding = parser.parse(raw_records)[0]
    result = abstraction.evaluate(finding)
    return explanation.build_explanation(finding, result)


def test_technical_view_contains_cve_and_tree_paths():
    exp = _build_explanation("qualys_json", DATA_DIR / "synthetic" / "scenario_a.json")
    html = render_technical(exp)

    assert "CVE-2024-3094" in html
    for step in exp.evidence_pointers["urgency"]["path"]:
        assert step in html


def test_nontechnical_view_excludes_cve_and_field_names():
    exp = _build_explanation("qualys_json", DATA_DIR / "synthetic" / "scenario_a.json")
    html = render_nontechnical(exp)

    assert "CVE-2024-3094" not in html
    assert "exploit_available" not in html
    assert "inputs_used" not in html


def test_both_views_share_same_explanation_object():
    exp = _build_explanation("isd_csv", DATA_DIR / "isd" / "scenario_a_terrapin.json")

    assert exp.time_horizon in render_technical(exp)
    assert exp.risk_summary in render_nontechnical(exp)
