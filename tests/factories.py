"""Test helper for building NormalisedFinding instances with defaults."""

from __future__ import annotations

from explainer.models import NormalisedFinding

_DEFAULTS = {
    "vulnerability_id": "CVE-2024-0001",
    "additional_cve_ids": [],
    "title": "Example finding",
    "severity": None,
    "severity_band": None,
    "cvss_score": None,
    "exploit_available": None,
    "known_exploited": None,
    "attack_vector": None,
    "patch_available": None,
    "patch_age_days": None,
    "days_open": None,
    "threshold_days": None,
    "solution_text": None,
    "asset_id": None,
    "hostname": None,
    "operating_system": None,
    "asset_environment": None,
    "asset_criticality": None,
    "asset_internet_facing": None,
    "status": None,
    "last_scan_date": None,
    "source_format": "qualys_json",
    "absent_by_format": frozenset(),
}


def make_finding(**overrides) -> NormalisedFinding:
    fields = dict(_DEFAULTS)
    fields.update(overrides)
    return NormalisedFinding(**fields)
