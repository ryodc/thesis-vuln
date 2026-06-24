"""Tests for the Flask app: routing, upload and pipeline wiring."""

from __future__ import annotations

import csv
import io

import pytest

from explainer.app import create_app


@pytest.fixture()
def client():
    app = create_app()
    client = app.test_client()
    client.post("/samples")
    return client


def test_index_shows_findings_after_loading_samples(client):
    response = client.get("/")

    assert response.status_code == 200
    body = response.data.decode()
    assert "findings-table" in body
    assert "badge-immediate" in body


def test_findings_are_sorted_immediate_before_scheduled(client):
    body = client.get("/").data.decode()

    assert body.index("badge-immediate") < body.index("badge-scheduled")


def test_finding_detail_renders_both_roles(client):
    for role in ("technical", "nontechnical"):
        response = client.get(f"/finding/0?role={role}")
        assert response.status_code == 200


def test_pipeline_view_shows_all_three_stages(client):
    body = client.get("/finding/0/pipeline").data.decode()

    assert "Stage 1" in body
    assert "Stage 2" in body
    assert "Stage 3" in body


def test_upload_adds_internal_vulnerability_and_filters_other_categories(client):
    fieldnames = [
        "Issue Category", "Issue Title", "CVE ID", "Severity", "Patchable",
        "Age", "Threshold", "Solution", "Asset Environment", "Remote Discovery",
        "Issue Status", "Operating System",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerow({
        "Issue Category": "Internal Vulnerabilities",
        "Issue Title": "Upload Test Finding",
        "CVE ID": "CVE-2099-0001",
        "Severity": "High",
        "Patchable": "Yes",
        "Age": "10",
        "Threshold": "90",
        "Asset Environment": "production",
        "Remote Discovery": "No",
        "Issue Status": "Active",
        "Operating System": "linux",
    })
    writer.writerow({"Issue Category": "Compliance", "Issue Title": "Should be filtered"})

    response = client.post(
        "/upload",
        data={"csv_file": (io.BytesIO(buf.getvalue().encode("utf-8-sig")), "test.csv")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    body = response.data.decode()
    assert "Added 1 finding" in body
    assert "Upload Test Finding" in body
    assert "Should be filtered" not in body
