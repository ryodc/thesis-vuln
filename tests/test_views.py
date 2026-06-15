"""Tests for the stakeholder view renderers.

Both renderers consume the same ExplanationObject. The technical view
must surface the evidence (tree paths, CVE, raw field names); the
non-technical view must not leak any of that.
"""

from __future__ import annotations

from explainer import abstraction, explanation
from explainer.ingestion import PARSERS
from explainer.views import RENDERERS, render_nontechnical, render_technical

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _build_explanation(source_format: str, path: Path):
    parser = PARSERS[source_format]
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw_records = [raw] if source_format == "isd_csv" else raw
    finding = parser.parse(raw_records)[0]
    result = abstraction.evaluate(finding)
    return explanation.build_explanation(finding, result)


def test_registry_contains_both_roles():
    assert set(RENDERERS) == {"technical", "nontechnical"}
    assert RENDERERS["technical"] is render_technical
    assert RENDERERS["nontechnical"] is render_nontechnical


def test_technical_view_contains_cve_and_tree_paths():
    explanation_object = _build_explanation("qualys_json", DATA_DIR / "synthetic" / "scenario_a.json")

    html = render_technical(explanation_object)

    assert "CVE-2024-3094" in html
    for step in explanation_object.evidence_pointers["urgency"]["path"]:
        assert step in html
    for step in explanation_object.evidence_pointers["exploitation_likelihood"]["path"]:
        assert step in html


def test_nontechnical_view_excludes_cve_and_field_names():
    explanation_object = _build_explanation("qualys_json", DATA_DIR / "synthetic" / "scenario_a.json")

    html = render_nontechnical(explanation_object)

    assert "CVE-2024-3094" not in html
    assert "exploit_available" not in html
    assert "asset_criticality" not in html
    assert "inputs_used" not in html
    assert "tree-path" not in html


def test_both_views_render_from_one_object():
    explanation_object = _build_explanation("isd_csv", DATA_DIR / "isd" / "scenario_a_terrapin.json")

    technical_html = render_technical(explanation_object)
    nontechnical_html = render_nontechnical(explanation_object)

    assert explanation_object.time_horizon in technical_html
    assert explanation_object.time_horizon in nontechnical_html
    assert explanation_object.risk_summary in nontechnical_html
    assert explanation_object.urgency.upper() in nontechnical_html


def test_role_toggle_links_use_finding_id():
    explanation_object = _build_explanation("qualys_json", DATA_DIR / "synthetic" / "scenario_a.json")

    technical_html = render_technical(explanation_object, finding_id="3")
    nontechnical_html = render_nontechnical(explanation_object, finding_id="3")

    assert "/finding/3?role=nontechnical" in technical_html
    assert "/finding/3?role=technical" in nontechnical_html
    assert "/finding/3/object" in technical_html


def test_renderer_without_finding_id_omits_role_toggle():
    explanation_object = _build_explanation("qualys_json", DATA_DIR / "synthetic" / "scenario_a.json")

    html = render_technical(explanation_object)

    assert "role-toggle" not in html
