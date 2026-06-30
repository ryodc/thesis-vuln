"""Verify the three abstraction trees as decision tables.

For each tree, the full Cartesian product of its decision-point value domains is
enumerated, the tree is run for every combination, and two properties are asserted:

- Completeness: every combination returns an outcome in the declared set; no
  combination raises or returns a value outside the enumerated outcomes.
- Consistency: running the same combination twice returns the same outcome (pure
  function regression guard).

The row count is asserted to equal the product of the domain sizes so a silently
dropped combination fails. Each generated table is written to
docs/decision_tables/ as a CSV for inclusion in the report appendix.

Value domains and valid outcome sets are read from config/ssvc.json so the test
and the SSVC documentation cannot drift apart.
"""

from __future__ import annotations

import csv
import itertools
import json
import math
from pathlib import Path

import pytest

from explainer.abstraction import (
    assess_exploitation_likelihood,
    assess_preliminary_impact,
    assess_urgency,
)
from explainer.models import TreeOutcome
from tests.factories import make_finding

ROOT = Path(__file__).resolve().parent.parent
SSVC = json.loads((ROOT / "config" / "ssvc.json").read_text(encoding="utf-8"))
TABLES_DIR = ROOT / "docs" / "decision_tables"

# Representative cvss_score per technical severity tier
_TIER_TO_CVSS = {"high": 9.8, "moderate": 5.0, "low": 2.0, None: None}

# Overdue flag → (days_open, threshold_days)
_OVERDUE_TO_DAYS = {True: (100, 90), False: (30, 90)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_table(name: str, rows: list[dict]) -> None:
    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    path = TABLES_DIR / f"{name}.csv"
    if not rows:
        return
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _domain_sizes(tree_name: str) -> int:
    tree = SSVC["trees"][tree_name]
    return math.prod(len(dp["values"]) for dp in tree["decision_points"])


def _valid_outcomes(tree_name: str) -> set[str]:
    return set(SSVC["trees"][tree_name]["outcomes"])


# ---------------------------------------------------------------------------
# Tree 1 — Exploitation likelihood
# ---------------------------------------------------------------------------


def test_exploitation_likelihood_completeness_and_consistency():
    tree = SSVC["trees"]["exploitation_likelihood"]
    valid = _valid_outcomes("exploitation_likelihood")
    domains = [dp["values"] for dp in tree["decision_points"]]
    # fields: exploit_available, known_exploited, asset_internet_facing

    rows = []
    for exploit_available, known_exploited, asset_internet_facing in itertools.product(*domains):
        finding = make_finding(
            exploit_available=exploit_available,
            known_exploited=known_exploited,
            asset_internet_facing=asset_internet_facing,
        )
        outcome1 = assess_exploitation_likelihood(finding)
        outcome2 = assess_exploitation_likelihood(finding)

        assert outcome1.value in valid, (
            f"outcome {outcome1.value!r} not in {valid} for "
            f"exploit_available={exploit_available}, known_exploited={known_exploited}, "
            f"asset_internet_facing={asset_internet_facing}"
        )
        assert outcome1.value == outcome2.value, "tree is not deterministic"

        rows.append({
            "exploit_available": exploit_available,
            "known_exploited": known_exploited,
            "asset_internet_facing": asset_internet_facing,
            "outcome": outcome1.value,
        })

    assert len(rows) == _domain_sizes("exploitation_likelihood"), (
        f"expected {_domain_sizes('exploitation_likelihood')} rows, got {len(rows)}"
    )
    _write_table("exploitation_likelihood", rows)


# ---------------------------------------------------------------------------
# Tree 2 — Impact
# ---------------------------------------------------------------------------


def test_impact_completeness_and_consistency():
    tree = SSVC["trees"]["impact"]
    valid = _valid_outcomes("impact")
    # fields: asset_environment, technical_severity_tier, asset_business_critical,
    #         asset_owner_privileged
    domains = [dp["values"] for dp in tree["decision_points"]]

    rows = []
    for env, tier, business_critical, owner_privileged in itertools.product(*domains):
        cvss = _TIER_TO_CVSS[tier]
        finding = make_finding(
            asset_environment=env,
            cvss_score=cvss,
            severity_band=None,
            asset_business_critical=business_critical,
            asset_owner_privileged=owner_privileged,
        )
        outcome1 = assess_preliminary_impact(finding)
        outcome2 = assess_preliminary_impact(finding)

        assert outcome1.value in valid, (
            f"outcome {outcome1.value!r} not in {valid} for "
            f"env={env}, tier={tier}, bc={business_critical}, op={owner_privileged}"
        )
        assert outcome1.value == outcome2.value, "tree is not deterministic"

        rows.append({
            "asset_environment": env,
            "technical_severity_tier": tier,
            "asset_business_critical": business_critical,
            "asset_owner_privileged": owner_privileged,
            "outcome": outcome1.value,
        })

    assert len(rows) == _domain_sizes("impact"), (
        f"expected {_domain_sizes('impact')} rows, got {len(rows)}"
    )
    _write_table("impact", rows)


# ---------------------------------------------------------------------------
# Tree 3 — Urgency
# ---------------------------------------------------------------------------


def _likelihood_outcome(value: str) -> TreeOutcome:
    return TreeOutcome(value=value, path=["decision-table fixture"], inputs_used={})


def test_urgency_completeness_and_consistency():
    tree = SSVC["trees"]["urgency"]
    valid = _valid_outcomes("urgency")
    # fields: exploitation_likelihood, patch_available, overdue, asset_internet_facing
    domains = [dp["values"] for dp in tree["decision_points"]]

    rows = []
    for ll_value, patch_available, overdue, asset_internet_facing in itertools.product(*domains):
        days_open, threshold_days = _OVERDUE_TO_DAYS[overdue]
        finding = make_finding(
            patch_available=patch_available,
            days_open=days_open,
            threshold_days=threshold_days,
            asset_internet_facing=asset_internet_facing,
        )
        likelihood = _likelihood_outcome(ll_value)
        outcome1 = assess_urgency(finding, likelihood)
        outcome2 = assess_urgency(finding, likelihood)

        assert outcome1.value in valid, (
            f"outcome {outcome1.value!r} not in {valid} for "
            f"ll={ll_value}, patch={patch_available}, overdue={overdue}, "
            f"internet_facing={asset_internet_facing}"
        )
        assert outcome1.value == outcome2.value, "tree is not deterministic"

        rows.append({
            "exploitation_likelihood": ll_value,
            "patch_available": patch_available,
            "overdue": overdue,
            "asset_internet_facing": asset_internet_facing,
            "outcome": outcome1.value,
        })

    assert len(rows) == _domain_sizes("urgency"), (
        f"expected {_domain_sizes('urgency')} rows, got {len(rows)}"
    )
    _write_table("urgency", rows)
