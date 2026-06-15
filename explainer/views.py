"""Stakeholder views: renders one ExplanationObject as HTML per role.

Renderer registry (Strategy pattern): adding a third role is one new
function plus one new template, with no changes to the other
renderers. Both renderers consume the identical ExplanationObject and
perform no computation of their own - everything they show was
already decided by the explanation layer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from jinja2 import Environment, FileSystemLoader, select_autoescape

from explainer.models import ExplanationObject

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)

URGENCY_BADGE_CLASSES = {
    "Immediate": "badge-immediate",
    "Scheduled": "badge-scheduled",
    "Monitor": "badge-monitor",
}
DEFAULT_BADGE_CLASS = "badge-unknown"

RENDERERS: dict[str, Callable[[ExplanationObject], str]] = {}


def register(role: str):
    """Decorator that adds a renderer to the role registry."""

    def decorator(func: Callable[[ExplanationObject], str]) -> Callable[[ExplanationObject], str]:
        RENDERERS[role] = func
        return func

    return decorator


def urgency_badge_class(urgency: str) -> str:
    return URGENCY_BADGE_CLASSES.get(urgency, DEFAULT_BADGE_CLASS)


@register("technical")
def render_technical(explanation: ExplanationObject, finding_id: str | None = None) -> str:
    template = _env.get_template("technical.html")
    return template.render(
        explanation=explanation,
        badge_class=urgency_badge_class(explanation.urgency),
        finding_id=finding_id,
    )


@register("nontechnical")
def render_nontechnical(explanation: ExplanationObject, finding_id: str | None = None) -> str:
    template = _env.get_template("nontechnical.html")
    return template.render(
        explanation=explanation,
        badge_class=urgency_badge_class(explanation.urgency),
        finding_id=finding_id,
    )


# ---------------------------------------------------------------------------
# Plain-text exports (Strategy pattern, same registry idea as RENDERERS)
# ---------------------------------------------------------------------------

TEXT_RENDERERS: dict[str, Callable[[ExplanationObject], str]] = {}


def register_text(role: str):
    """Decorator that adds a plain-text renderer to the text registry."""

    def decorator(func: Callable[[ExplanationObject], str]) -> Callable[[ExplanationObject], str]:
        TEXT_RENDERERS[role] = func
        return func

    return decorator


@register_text("technical")
def render_technical_text(explanation: ExplanationObject) -> str:
    title = explanation.title or "Untitled finding"
    detail = explanation.technical_detail
    pointers = explanation.evidence_pointers

    lines = [
        title,
        "=" * len(title),
        "",
        f"CVE: {explanation.vulnerability_id or 'No CVE identifier'}",
        f"Urgency: {explanation.urgency}",
        f"Certainty: {explanation.certainty_level}",
        "",
        "Ratings and evidence",
        "---------------------",
        f"Exploitation likelihood: {detail['exploitation_likelihood']}",
    ]
    for step in pointers["exploitation_likelihood"]["path"]:
        lines.append(f"  - {step}")
    lines.append(f"  inputs used: {pointers['exploitation_likelihood']['inputs']}")
    lines.append("")
    lines.append(f"Business impact: {detail['business_impact']}")
    for step in pointers["business_impact"]["path"]:
        lines.append(f"  - {step}")
    lines.append(f"  inputs used: {pointers['business_impact']['inputs']}")
    lines.append("")
    lines.append(f"Urgency: {explanation.urgency}")
    for step in pointers["urgency"]["path"]:
        lines.append(f"  - {step}")
    lines.append(f"  inputs used: {pointers['urgency']['inputs']}")
    lines.append("")

    lines.append("Top factors")
    lines.append("-----------")
    for factor in explanation.top_factors:
        lines.append(f"- {factor['field']} = {factor['value']}: {factor['label']}")
    lines.append("")

    lines.append("Asset context")
    lines.append("-------------")
    lines.append(f"Status: {detail['status'] or 'Unknown'}")
    lines.append(f"Operating system: {detail['operating_system'] or 'Unknown'}")
    lines.append(f"Environment: {detail['asset_environment'] or 'Unknown'}")
    cvss = f" (CVSS {detail['cvss_score']})" if detail["cvss_score"] is not None else ""
    lines.append(f"Severity band / CVSS: {detail['severity_band'] or 'Unknown'}{cvss}")
    if detail["days_open"] is not None and detail["threshold_days"] is not None:
        delta = detail["days_open"] - detail["threshold_days"]
        status_word = "overdue" if delta > 0 else "remaining"
        lines.append(
            f"Days open vs threshold: {detail['days_open']} days open against a "
            f"{detail['threshold_days']}-day threshold ({delta} days {status_word})"
        )
    lines.append("")

    if detail["solution_text"]:
        lines.append("Vendor solution")
        lines.append("---------------")
        lines.append(detail["solution_text"])
        lines.append("")

    lines.append("Recommended action")
    lines.append("-------------------")
    lines.append(explanation.action)
    lines.append(explanation.time_horizon)
    lines.append("")

    if explanation.mitigation:
        lines.append("Temporary mitigation")
        lines.append("---------------------")
        lines.append(explanation.mitigation)
        lines.append("")

    if explanation.limitations:
        lines.append("Limitations")
        lines.append("-----------")
        lines.append(explanation.limitations)
        lines.append("")

    return "\n".join(lines)


@register_text("nontechnical")
def render_nontechnical_text(explanation: ExplanationObject) -> str:
    title = explanation.title or "Security finding"

    lines = [
        title,
        "=" * len(title),
        "",
        f"Urgency: {explanation.urgency.upper()}",
        "",
        explanation.risk_summary,
        "",
        "What could happen",
        "------------------",
        explanation.business_consequence,
        "",
        "When",
        "----",
        explanation.time_horizon,
        "",
        "What to do",
        "----------",
        explanation.action,
    ]

    if explanation.mitigation:
        lines.append(explanation.mitigation)

    if explanation.certainty_level != "Known" and explanation.limitations:
        lines.append("")
        lines.append("What this assessment could not take into account")
        lines.append("--------------------------------------------------")
        lines.append(explanation.limitations)

    return "\n".join(lines)
