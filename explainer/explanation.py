"""Builds the ExplanationObject: the central, audience-independent explanation.

Pipeline within this layer: content selection -> certainty derivation
-> template filling -> mitigation -> limitations. This mirrors Reiter
& Dale's content-selection / aggregation / realisation stages of NLG,
applied to structured data.

Nothing here reads from the source format; everything operates on
NormalisedFinding and AbstractionResult.
"""

from __future__ import annotations

import dataclasses
import re

from explainer.config import TEMPLATES
from explainer.models import AbstractionResult, ExplanationObject, NormalisedFinding, TreeOutcome

_FINDING_FIELD_NAMES = {field.name for field in dataclasses.fields(NormalisedFinding)}

SOURCE_DISPLAY_NAMES = {
    "isd_csv": "ISD",
    "qualys_json": "Qualys",
}

_SOLUTION_EXCERPT_MAX_LENGTH = 200


# ---------------------------------------------------------------------------
# 7.1 Content selection
# ---------------------------------------------------------------------------


def _internet_facing_label(finding: NormalisedFinding, value: object) -> str:
    if value:
        return "the affected system is reachable from the internet"
    return "the affected system is not reachable from the internet"


def _patch_available_label(finding: NormalisedFinding, value: object) -> str:
    if value:
        return "a vendor patch is available"
    return "no vendor patch is currently available"


def _exploit_available_label(finding: NormalisedFinding, value: object) -> str:
    if value:
        return "a public exploit is available for this vulnerability"
    return "no public exploit is currently known for this vulnerability"


def _known_exploited_label(finding: NormalisedFinding, value: object) -> str:
    if value:
        return "active exploitation has been observed in the wild"
    return "no active exploitation has been reported"


def _asset_criticality_label(finding: NormalisedFinding, value: object) -> str:
    environment = finding.asset_environment or "affected"
    return f"{str(value).lower()}-criticality {environment} system"


def _asset_environment_label(finding: NormalisedFinding, value: object) -> str:
    if value is None:
        return "asset environment not specified"
    if str(value).strip().lower() == "production":
        return "production system"
    return f"{value} (non-production) system"


_FACTOR_LABEL_BUILDERS = {
    "asset_internet_facing": _internet_facing_label,
    "patch_available": _patch_available_label,
    "exploit_available": _exploit_available_label,
    "known_exploited": _known_exploited_label,
    "asset_environment": _asset_environment_label,
    "asset_criticality": _asset_criticality_label,
}

_TOP_FACTOR_CAP = 3


def _days_open_factor(inputs_used: dict) -> dict:
    days_open = inputs_used["days_open"]
    threshold = inputs_used["threshold_days"]
    if days_open > threshold:
        overdue = days_open - threshold
        label = f"open {days_open} days, {overdue} days past the {threshold}-day threshold"
    else:
        label = f"open {days_open} days, within the {threshold}-day threshold"
    return {"label": label, "field": "days_open", "value": days_open}


def _factors_from_inputs(finding: NormalisedFinding, inputs_used: dict, seen_fields: set) -> list[dict]:
    factors = []
    has_threshold = "threshold_days" in inputs_used

    for field, value in inputs_used.items():
        if field in seen_fields:
            continue

        if field == "days_open" and has_threshold:
            factors.append(_days_open_factor(inputs_used))
            seen_fields.add("days_open")
            seen_fields.add("threshold_days")
            continue

        if field == "threshold_days":
            continue

        if field not in _FACTOR_LABEL_BUILDERS:
            continue

        label = _FACTOR_LABEL_BUILDERS[field](finding, value)
        factors.append({"label": label, "field": field, "value": value})
        seen_fields.add(field)

    return factors


def select_top_factors(finding: NormalisedFinding, abstraction: AbstractionResult) -> list[dict]:
    """Pick up to three factors from the decisive tree paths.

    Priority order: urgency path, then exploitation likelihood path
    (unless its value is Unknown), then business impact path. The
    conditions on the decisive paths *are* the most relevant factors,
    so no separate ranking heuristic is needed.
    """

    seen_fields: set[str] = set()
    factors = _factors_from_inputs(finding, abstraction.urgency.inputs_used, seen_fields)

    if abstraction.exploitation_likelihood.value != "Unknown":
        factors += _factors_from_inputs(finding, abstraction.exploitation_likelihood.inputs_used, seen_fields)

    factors += _factors_from_inputs(finding, abstraction.business_impact.inputs_used, seen_fields)

    return factors[:_TOP_FACTOR_CAP]


# ---------------------------------------------------------------------------
# 7.2 Certainty derivation
# ---------------------------------------------------------------------------


def _required_fields(abstraction: AbstractionResult) -> set[str]:
    keys = set()
    keys |= abstraction.exploitation_likelihood.inputs_used.keys()
    keys |= abstraction.business_impact.inputs_used.keys()
    keys |= abstraction.urgency.inputs_used.keys()
    return keys & _FINDING_FIELD_NAMES


def derive_certainty(finding: NormalisedFinding, abstraction: AbstractionResult) -> str:
    """Classify how trustworthy the rating is, per the knowability framework.

    - Unknowable: no CVE identifier exists for this finding (it is an
      EOL or misconfiguration detection), so exploitability is
      undefined in principle.
    - Known: every field the trees attempted to read is present.
    - Known uncertainty: the missing fields are exactly the ones this
      source format is documented to never provide.
    - Unknown uncertainty: a field that the source normally provides
      is unexpectedly null.
    """

    if finding.vulnerability_id is None:
        return "Unknowable"

    required = _required_fields(abstraction)
    missing = {field for field in required if getattr(finding, field) is None}

    if not missing:
        return "Known"
    if missing <= finding.absent_by_format:
        return "Known uncertainty"
    return "Unknown uncertainty"


# ---------------------------------------------------------------------------
# 7.3 Template filling
# ---------------------------------------------------------------------------


def _risk_summary(abstraction: AbstractionResult, top_factors: list[dict]) -> str:
    likelihood_unknown = abstraction.exploitation_likelihood.value == "Unknown"
    prefix = "unknown_likelihood" if likelihood_unknown else "known"

    if not top_factors:
        factor_1 = "the available evidence"
        key = f"{prefix}_one_factor"
        return TEMPLATES["risk_summary"][key].format(urgency=abstraction.urgency.value, factor_1=factor_1)

    if len(top_factors) == 1:
        key = f"{prefix}_one_factor"
        return TEMPLATES["risk_summary"][key].format(
            urgency=abstraction.urgency.value,
            factor_1=top_factors[0]["label"],
        )

    key = f"{prefix}_two_factor"
    return TEMPLATES["risk_summary"][key].format(
        urgency=abstraction.urgency.value,
        factor_1=top_factors[0]["label"],
        factor_2=top_factors[1]["label"],
    )


def _business_consequence(business_impact: TreeOutcome) -> str:
    return TEMPLATES["business_consequence"][business_impact.value]


def _time_horizon(urgency: TreeOutcome) -> str:
    return TEMPLATES["time_horizon"][urgency.value]


def _solution_excerpt(solution_text: str) -> str:
    first_sentence_match = re.search(r"^(.*?[.!?])(\s|$)", solution_text)
    excerpt = first_sentence_match.group(1) if first_sentence_match else solution_text
    return excerpt[:_SOLUTION_EXCERPT_MAX_LENGTH]


def _vendor_reference(finding: NormalisedFinding) -> str:
    if finding.solution_text:
        return TEMPLATES["action"]["vendor_ref_present"].format(
            solution_excerpt=_solution_excerpt(finding.solution_text)
        )
    return TEMPLATES["action"]["vendor_ref_absent"]


def _action(finding: NormalisedFinding) -> str:
    vendor_ref = _vendor_reference(finding)
    key = "patch" if finding.patch_available else "no_patch"
    return TEMPLATES["action"][key].format(vendor_ref=vendor_ref)


# ---------------------------------------------------------------------------
# 7.4 Mitigation population (ADR-0005)
# ---------------------------------------------------------------------------


def _mitigation(finding: NormalisedFinding, urgency: TreeOutcome) -> str | None:
    if finding.patch_available is False:
        return TEMPLATES["mitigation"]["no_patch"]
    if urgency.value == "Immediate":
        return TEMPLATES["mitigation"]["immediate_with_patch"]
    return None


# ---------------------------------------------------------------------------
# 7.5 Limitations
# ---------------------------------------------------------------------------


def _limitations(finding: NormalisedFinding, abstraction: AbstractionResult) -> str | None:
    sentences: list[str] = []

    if "exploit_available" in abstraction.exploitation_likelihood.inputs_used and (
        "exploit_available" in finding.absent_by_format
    ):
        source = SOURCE_DISPLAY_NAMES.get(finding.source_format, finding.source_format)
        sentences.append(
            "Exploit availability and active exploitation data are not included in the "
            f"{source} data source, so exploitation likelihood could not be assessed."
        )

    if finding.source_format == "isd_csv" and finding.asset_environment is not None:
        sentences.append(
            "Impact is a preliminary assessment based on the asset environment and the "
            "scanner's categorical severity; asset criticality, business service, and data "
            "sensitivity were not available in the source."
        )

    if finding.vulnerability_id is None:
        sentences.append(
            "No CVE identifier is associated with this finding; it was detected as "
            "end-of-life or misconfigured software."
        )

    if not sentences:
        return None

    sentences.append("The system does not determine asset ownership or final remediation decisions.")
    return " ".join(sentences)


# ---------------------------------------------------------------------------
# Evidence pointers and technical detail
# ---------------------------------------------------------------------------


def _evidence_pointers(abstraction: AbstractionResult) -> dict:
    return {
        "exploitation_likelihood": {
            "inputs": abstraction.exploitation_likelihood.inputs_used,
            "path": abstraction.exploitation_likelihood.path,
        },
        "business_impact": {
            "inputs": abstraction.business_impact.inputs_used,
            "path": abstraction.business_impact.path,
        },
        "urgency": {
            "inputs": abstraction.urgency.inputs_used,
            "path": abstraction.urgency.path,
        },
    }


def _technical_detail(finding: NormalisedFinding, abstraction: AbstractionResult) -> dict:
    return {
        "exploitation_likelihood": abstraction.exploitation_likelihood.value,
        "business_impact": abstraction.business_impact.value,
        "cvss_score": finding.cvss_score,
        "severity_band": finding.severity_band,
        "status": finding.status,
        "operating_system": finding.operating_system,
        "asset_environment": finding.asset_environment,
        "days_open": finding.days_open,
        "threshold_days": finding.threshold_days,
        "solution_text": finding.solution_text,
        "additional_cve_ids": finding.additional_cve_ids,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_explanation(finding: NormalisedFinding, abstraction: AbstractionResult) -> ExplanationObject:
    """Assemble the ExplanationObject for one finding."""

    top_factors = select_top_factors(finding, abstraction)

    return ExplanationObject(
        vulnerability_id=finding.vulnerability_id,
        risk_summary=_risk_summary(abstraction, top_factors),
        certainty_level=derive_certainty(finding, abstraction),
        top_factors=top_factors,
        business_consequence=_business_consequence(abstraction.business_impact),
        urgency=abstraction.urgency.value,
        time_horizon=_time_horizon(abstraction.urgency),
        action=_action(finding),
        mitigation=_mitigation(finding, abstraction.urgency),
        evidence_pointers=_evidence_pointers(abstraction),
        limitations=_limitations(finding, abstraction),
        title=finding.title,
        technical_detail=_technical_detail(finding, abstraction),
    )
