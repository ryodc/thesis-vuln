"""Tests for the Flask app: routing, upload, pipeline trace and export.

These exercise the composition root (`explainer.app`), which is the only
module allowed to wire ingestion, abstraction, explanation and views
together.
"""

from __future__ import annotations

import csv
import io

import pytest

from explainer.app import create_app


@pytest.fixture()
def empty_client():
    app = create_app()
    return app.test_client()


@pytest.fixture()
def client(empty_client):
    """A client with the bundled sample scenarios loaded."""

    empty_client.post("/samples")
    return empty_client


def test_index_is_empty_until_samples_are_loaded(empty_client):
    response = empty_client.get("/")

    assert response.status_code == 200
    body = response.data.decode()
    assert "csv_file" in body
    assert "Load sample scenarios" in body
    assert "findings-table" not in body
    assert "badge-immediate" not in body


def test_loading_samples_populates_index(empty_client):
    response = empty_client.post("/samples", follow_redirects=True)

    assert response.status_code == 200
    body = response.data.decode()
    assert "findings-table" in body
    assert "badge-immediate" in body


def test_index_lists_bundled_findings_sorted_by_urgency(client):
    response = client.get("/")

    assert response.status_code == 200
    body = response.data.decode()
    immediate_index = body.index("badge-immediate")
    monitor_index = body.find("badge-monitor")
    scheduled_index = body.index("badge-scheduled")

    assert immediate_index < scheduled_index
    # No "Monitor" findings are bundled, so badge-monitor should not appear.
    assert monitor_index == -1


def test_index_filters_by_urgency(client):
    response = client.get("/?urgency=Immediate")

    assert response.status_code == 200
    body = response.data.decode()
    assert "badge-immediate" in body
    assert "badge-scheduled" not in body
    assert "badge-monitor" not in body


def test_index_filters_by_search_query(client):
    all_findings = client.get("/").data.decode()
    assert "Findings" in all_findings

    response = client.get("/?q=nonexistent-search-term-xyz")

    assert response.status_code == 200
    body = response.data.decode()
    assert "No findings match this filter" in body


def test_index_with_few_findings_has_no_pagination(client):
    response = client.get("/")

    assert response.status_code == 200
    body = response.data.decode()
    assert "pagination" not in body


def test_finding_pages_link_back_to_findings(client):
    for path in (
        "/finding/0?role=technical",
        "/finding/0?role=nontechnical",
        "/finding/0/pipeline",
    ):
        response = client.get(path)
        body = response.data.decode()
        assert '<a href="/">&laquo; Back to findings</a>' in body


def test_finding_detail_unknown_id_is_404(client):
    response = client.get("/finding/does-not-exist")

    assert response.status_code == 404


def test_finding_detail_unknown_role_is_404(client):
    response = client.get("/finding/0?role=executive")

    assert response.status_code == 404



def test_pipeline_view_shows_all_three_stages(client):
    response = client.get("/finding/0/pipeline")

    assert response.status_code == 200
    body = response.data.decode()
    assert "Stage 1" in body
    assert "Stage 2" in body
    assert "Stage 3" in body
    # Stage 1 should expose raw ingestion fields not shown in the other views.
    assert "Source format" in body
    assert "qualys_json" in body



def test_upload_form_renders(client):
    response = client.get("/upload")

    assert response.status_code == 200
    assert b"Upload" in response.data


def _csv_bytes(rows: list[dict]) -> bytes:
    fieldnames = [
        "Issue Category", "Issue Title", "CVE ID", "Severity", "Patchable",
        "CVE Age", "Age", "Threshold", "Solution", "Operating System",
        "Asset Environment", "Remote Discovery", "Issue Status", "Last Scan Date",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row.get(name, "") for name in fieldnames})
    return buf.getvalue().encode("utf-8-sig")


def test_upload_adds_internal_vulnerability_rows_and_filters_others(client):
    csv_bytes = _csv_bytes(
        [
            {
                "Issue Category": "Internal Vulnerabilities",
                "Issue Title": "Uploaded Test Finding",
                "CVE ID": "CVE-2099-0001",
                "Severity": "Medium",
                "Patchable": "Yes",
                "Age": "5",
                "Threshold": "90",
                "Solution": "Apply the test patch.",
                "Operating System": "Ubuntu 24.04",
                "Asset Environment": "staging",
                "Remote Discovery": "No",
                "Issue Status": "Active",
                "Last Scan Date": "06/01/2026",
            },
            {
                "Issue Category": "Compliance",
                "Issue Title": "Should be filtered out",
            },
        ]
    )

    response = client.post(
        "/upload",
        data={"csv_file": (io.BytesIO(csv_bytes), "upload.csv")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    body = response.data.decode()
    assert "Added 1 finding" in body
    assert "Uploaded Test Finding" in body
    assert "Should be filtered out" not in body


def test_upload_without_file_shows_error(client):
    response = client.post("/upload", data={}, content_type="multipart/form-data")

    assert response.status_code == 200
    assert b"choose a CSV file" in response.data


def test_upload_with_no_matching_rows_reports_zero(client):
    csv_bytes = _csv_bytes([{"Issue Category": "Compliance", "Issue Title": "Irrelevant"}])

    response = client.post(
        "/upload",
        data={"csv_file": (io.BytesIO(csv_bytes), "upload.csv")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"No" in response.data and b"Internal Vulnerabilities" in response.data
