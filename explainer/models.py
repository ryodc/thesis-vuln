"""Shared data structures passed between pipeline layers.

These dataclasses are the explicit, machine-checked contracts between
layers: ingestion produces NormalisedFinding, abstraction produces
AbstractionResult, explanation produces ExplanationObject.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NormalisedFinding:
    """A single vulnerability finding in the source-independent schema."""

    # identity
    vulnerability_id: str | None
    additional_cve_ids: list[str]
    title: str | None

    # severity signals
    severity: int | None
    severity_band: str | None
    cvss_score: float | None
    exploit_available: bool | None
    known_exploited: bool | None
    attack_vector: str | None

    # remediation signals
    patch_available: bool | None
    patch_age_days: int | None
    days_open: int | None
    threshold_days: int | None
    solution_text: str | None

    # asset context
    asset_id: str | None
    hostname: str | None
    operating_system: str | None
    asset_environment: str | None
    asset_criticality: str | None
    asset_internet_facing: bool | None

    # lifecycle
    status: str | None
    last_scan_date: str | None

    # provenance
    source_format: str
    absent_by_format: frozenset[str]

    # asset business criticality, present when the asset resolved in the CMDB
    # during ingestion; None when no asset record was available.
    asset_business_critical: bool | None = None

    # asset owner privilege, present when the owner resolved in the identity
    # table during ingestion. Only the boolean is stored; the owner's name and
    # email are never written onto the finding.
    asset_owner_privileged: bool | None = None


@dataclass(frozen=True)
class TreeOutcome:
    """The result of one decision-tree traversal, with its trace."""

    value: str
    path: list[str]
    inputs_used: dict[str, object]


@dataclass(frozen=True)
class AbstractionResult:
    """The three rated outcomes produced by the abstraction layer."""

    exploitation_likelihood: TreeOutcome
    business_impact: TreeOutcome
    urgency: TreeOutcome


@dataclass
class ExplanationObject:
    """The central, audience-independent explanation structure."""

    vulnerability_id: str | None
    risk_summary: str
    certainty_level: str
    top_factors: list[dict]
    business_consequence: str
    urgency: str
    time_horizon: str
    action: str
    mitigation: str | None
    evidence_pointers: dict
    limitations: str | None
    asset_context_note: str | None

    # render support (presentation metadata, not part of the thesis
    # ExplanationObject schema)
    title: str | None
    technical_detail: dict
