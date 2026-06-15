"""Loads the JSON configuration files at import time.

Both the ingestion and abstraction layers need the numeric bands and
thresholds, so they live here as a shared, dependency-free leaf module
(like models.py, it imports nothing from the rest of explainer).
"""

from __future__ import annotations

import json
from pathlib import Path

_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def _load(name: str) -> dict:
    with open(_CONFIG_DIR / name, encoding="utf-8") as config_file:
        return json.load(config_file)


THRESHOLDS = _load("thresholds.json")
TEMPLATES = _load("templates.json")


def cvss_score_to_band(cvss_score: float | None) -> str | None:
    """Map a numeric CVSS score to an NVD severity band, or None."""
    if cvss_score is None:
        return None

    bands = THRESHOLDS["cvss_bands"]
    if cvss_score >= bands["critical_min"]:
        return "Critical"
    if cvss_score >= bands["high_min"]:
        return "High"
    if cvss_score >= bands["medium_min"]:
        return "Medium"
    return "Low"


def risk_score_to_criticality(risk_score: float | None) -> str | None:
    """Map a numeric asset risk score to High/Medium/Low, or None."""
    if risk_score is None:
        return None

    bands = THRESHOLDS["asset_risk_score_bands"]
    if risk_score >= bands["high_min"]:
        return "High"
    if risk_score >= bands["medium_min"]:
        return "Medium"
    return "Low"
