"""Flask entry point: wires the four layers together for the prototype UI.

The findings store starts empty. The bundled synthetic and ISD scenario
files (the thesis's worked examples, see Section 9 of the master plan) can
be loaded on demand via `/samples`, and uploading a CSV (see `/upload`) runs
additional findings through the same pipeline. Both paths add to the same
in-memory store, run through ingestion, abstraction and explanation. The
routes below only select, render and export results that the pipeline has
already produced.
"""

from __future__ import annotations

import csv
import dataclasses
import io
import itertools
import json
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, url_for

from explainer import abstraction, explanation
from explainer.ingestion import PARSERS
from explainer.views import RENDERERS, urgency_badge_class

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

SOURCE_FILES = [
    ("qualys_json", DATA_DIR / "synthetic" / "scenario_a.json"),
    ("qualys_json", DATA_DIR / "synthetic" / "scenario_b.json"),
    ("qualys_json", DATA_DIR / "synthetic" / "scenario_c.json"),
    ("isd_csv", DATA_DIR / "isd" / "scenario_a_terrapin.json"),
    ("isd_csv", DATA_DIR / "isd" / "scenario_b_putty.json"),
    ("isd_csv", DATA_DIR / "isd" / "scenario_c_python_eol.json"),
]

URGENCY_ORDER = {"Immediate": 0, "Scheduled": 1, "Monitor": 2}
URGENCY_FILTER_OPTIONS = ["Immediate", "Scheduled", "Monitor"]
FINDINGS_PER_PAGE = 50


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(PROJECT_ROOT / "templates"),
        static_folder=str(PROJECT_ROOT / "static"),
    )

    findings_by_id: dict[str, dict] = {}
    next_id = itertools.count()

    def _register(finding) -> str:
        result = abstraction.evaluate(finding)
        explanation_object = explanation.build_explanation(finding, result)
        finding_id = str(next(next_id))
        findings_by_id[finding_id] = {
            "id": finding_id,
            "finding": finding,
            "abstraction": result,
            "explanation": explanation_object,
        }
        return finding_id

    def _load_sample_findings() -> list[str]:
        new_ids = []
        for source_format, path in SOURCE_FILES:
            parser = PARSERS[source_format]
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw_records = [raw] if source_format == "isd_csv" else raw
            for finding in parser.parse(raw_records):
                new_ids.append(_register(finding))
        return new_ids

    @app.route("/")
    def index():
        urgency_filter = request.args.get("urgency", "")
        query = request.args.get("q", "").strip().lower()
        page = max(request.args.get("page", 1, type=int), 1)

        rows = sorted(
            findings_by_id.values(),
            key=lambda row: URGENCY_ORDER.get(row["explanation"].urgency, len(URGENCY_ORDER)),
        )

        if urgency_filter:
            rows = [row for row in rows if row["explanation"].urgency == urgency_filter]

        if query:
            rows = [
                row
                for row in rows
                if query in (row["explanation"].title or "").lower()
                or query in (row["explanation"].vulnerability_id or "").lower()
            ]

        total = len(rows)
        total_pages = max((total + FINDINGS_PER_PAGE - 1) // FINDINGS_PER_PAGE, 1)
        page = min(page, total_pages)
        start = (page - 1) * FINDINGS_PER_PAGE
        page_rows = rows[start : start + FINDINGS_PER_PAGE]

        view_rows = [
            {
                "id": row["id"],
                "title": row["explanation"].title,
                "vulnerability_id": row["explanation"].vulnerability_id,
                "urgency": row["explanation"].urgency,
                "badge_class": urgency_badge_class(row["explanation"].urgency),
                "source_label": explanation.SOURCE_DISPLAY_NAMES.get(
                    row["finding"].source_format, row["finding"].source_format
                ),
            }
            for row in page_rows
        ]
        uploaded = request.args.get("uploaded", type=int)
        return render_template(
            "index.html",
            findings=view_rows,
            has_any_findings=bool(findings_by_id),
            uploaded=uploaded,
            urgency_filter=urgency_filter,
            urgency_options=URGENCY_FILTER_OPTIONS,
            query=query,
            total=total,
            page=page,
            total_pages=total_pages,
            start=start,
        )

    @app.route("/samples", methods=["POST"])
    def load_samples():
        _load_sample_findings()
        return redirect(url_for("index"))

    @app.route("/upload", methods=["GET"])
    def upload_form():
        return render_template("upload.html", error=None, added=None, new_ids=[])

    @app.route("/upload", methods=["POST"])
    def upload_csv():
        uploaded = request.files.get("csv_file")
        if uploaded is None or uploaded.filename == "":
            return render_template("upload.html", error="Please choose a CSV file.", added=None, new_ids=[])

        text = uploaded.read().decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(text)))
        new_findings = PARSERS["isd_csv"].parse(rows)
        new_ids = [_register(finding) for finding in new_findings]

        return redirect(url_for("index", uploaded=len(new_ids)))

    @app.route("/finding/<finding_id>")
    def finding_detail(finding_id: str):
        row = findings_by_id.get(finding_id)
        if row is None:
            abort(404)

        role = request.args.get("role", "technical")
        renderer = RENDERERS.get(role)
        if renderer is None:
            abort(404)

        return renderer(row["explanation"], finding_id=finding_id)

    @app.route("/finding/<finding_id>/pipeline")
    def finding_pipeline(finding_id: str):
        row = findings_by_id.get(finding_id)
        if row is None:
            abort(404)

        return render_template(
            "pipeline.html",
            finding_id=finding_id,
            finding=dataclasses.asdict(row["finding"]),
            explanation=row["explanation"],
        )

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
