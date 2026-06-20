"""The three decision trees that turn raw fields into stakeholder concepts.

Each tree is an explicit function that evaluates its branches in a
documented priority order, builds a human-readable `path` describing
the branch taken, and records every field it reads in `inputs_used`.
The trees never raise and always return a value from their enumerated
set (including "Unknown" where the source data does not allow a
rating).

Thresholds and matrices are loaded from config/thresholds.json so that
the rule values can change without a code edit.
"""

from __future__ import annotations

from explainer.config import THRESHOLDS, cvss_score_to_band
from explainer.models import AbstractionResult, NormalisedFinding, TreeOutcome

_PRODUCTION_IMPACT = {"high": "High", "moderate": "Medium", "low": "Low"}
_NONPRODUCTION_IMPACT = {"high": "Medium", "moderate": "Low", "low": "Low"}


def assess_exploitation_likelihood(finding: NormalisedFinding) -> TreeOutcome:
    """Tree 1: how likely is exploitation, based on exploit and exposure signals."""

    if finding.exploit_available is None:
        return TreeOutcome(
            value="Unknown",
            path=["exploit availability not provided by source"],
            inputs_used={"exploit_available": None},
        )

    if finding.exploit_available:
        if finding.known_exploited:
            return TreeOutcome(
                value="High",
                path=["public exploit available and active exploitation observed in the wild"],
                inputs_used={"exploit_available": True, "known_exploited": True},
            )
        if finding.asset_internet_facing:
            return TreeOutcome(
                value="High",
                path=["public exploit available and the asset is internet-facing"],
                inputs_used={
                    "exploit_available": True,
                    "known_exploited": finding.known_exploited,
                    "asset_internet_facing": True,
                },
            )
        return TreeOutcome(
            value="Medium",
            path=["public exploit available, but the asset is not internet-facing"],
            inputs_used={
                "exploit_available": True,
                "known_exploited": finding.known_exploited,
                "asset_internet_facing": finding.asset_internet_facing,
            },
        )

    if finding.known_exploited:
        return TreeOutcome(
            value="Medium",
            path=["exploitation reported despite no public exploit being available"],
            inputs_used={"exploit_available": False, "known_exploited": True},
        )
    return TreeOutcome(
        value="Low",
        path=["no public exploit available and no known exploitation"],
        inputs_used={"exploit_available": False, "known_exploited": finding.known_exploited},
    )


def _technical_severity_tier(finding: NormalisedFinding) -> tuple[str | None, str | None]:
    """Return (tier, band): tier in {high, moderate, low} or None.

    The band comes from the numeric CVSS score where present, otherwise
    from the scanner's categorical severity band. Critical and High
    bands are both treated as high technical severity.
    """
    band = cvss_score_to_band(finding.cvss_score)
    if band is None:
        band = finding.severity_band
    if band in ("Critical", "High"):
        return "high", band
    if band == "Medium":
        return "moderate", band
    if band == "Low":
        return "low", band
    return None, band


def assess_preliminary_impact(finding: NormalisedFinding) -> TreeOutcome:
    """Tree 2: preliminary impact from asset environment and technical severity.

    This is a preliminary assessment, not a complete business-impact
    rating. The source export carries no asset criticality, business
    service, or data sensitivity, so the highest level reachable is
    High. The asset environment is read directly rather than via an
    environment-derived criticality proxy (ADR-0007).
    """
    tier, band = _technical_severity_tier(finding)
    inputs_used: dict[str, object] = {
        "asset_environment": finding.asset_environment,
        "technical_severity": band,
    }

    if finding.asset_environment is None or tier is None:
        return TreeOutcome(
            value="Unknown",
            path=["asset environment or technical severity not available"],
            inputs_used=inputs_used,
        )

    production = finding.asset_environment.strip().lower() == "production"
    env_label = "production" if production else "non-production"
    value = (_PRODUCTION_IMPACT if production else _NONPRODUCTION_IMPACT)[tier]

    return TreeOutcome(
        value=value,
        path=[
            f"asset environment {env_label}; technical severity band {band}",
            f"{env_label} asset with {band} severity → {value}",
        ],
        inputs_used=inputs_used,
    )


def assess_urgency(finding: NormalisedFinding, likelihood: TreeOutcome) -> TreeOutcome:
    """Tree 3: urgency from likelihood, patch status, age and exposure.

    Includes the Unknown-likelihood branch (ADR-0004): when
    exploitability cannot be assessed, exposure plus SLA breach is the
    strongest remaining evidence for prioritisation.
    """

    threshold = (
        finding.threshold_days
        if finding.threshold_days is not None
        else THRESHOLDS["default_threshold_days"]
    )
    overdue = finding.days_open is not None and finding.days_open > threshold

    if likelihood.value == "High":
        return TreeOutcome(
            value="Immediate",
            path=["exploitation likelihood is High → Immediate regardless of patch status or age"],
            inputs_used={"exploitation_likelihood": "High"},
        )

    if likelihood.value == "Medium":
        inputs_used = {"exploitation_likelihood": "Medium", "patch_available": finding.patch_available}
        if finding.patch_available and overdue:
            inputs_used["days_open"] = finding.days_open
            inputs_used["threshold_days"] = threshold
            return TreeOutcome(
                value="Immediate",
                path=[
                    "exploitation likelihood is Medium",
                    f"a patch is available and the finding is {finding.days_open - threshold} "
                    f"days past the {threshold}-day remediation threshold → Immediate",
                ],
                inputs_used=inputs_used,
            )
        if finding.patch_available:
            inputs_used["days_open"] = finding.days_open
            inputs_used["threshold_days"] = threshold
        return TreeOutcome(
            value="Scheduled",
            path=[
                "exploitation likelihood is Medium",
                "not yet overdue, or no patch available → Scheduled",
            ],
            inputs_used=inputs_used,
        )

    if likelihood.value == "Low":
        inputs_used = {"exploitation_likelihood": "Low", "patch_available": finding.patch_available}
        if finding.patch_available and overdue:
            inputs_used["days_open"] = finding.days_open
            inputs_used["threshold_days"] = threshold
            return TreeOutcome(
                value="Scheduled",
                path=[
                    "exploitation likelihood is Low",
                    f"a patch is available and the finding is {finding.days_open - threshold} "
                    f"days past the {threshold}-day remediation threshold → Scheduled",
                ],
                inputs_used=inputs_used,
            )
        if finding.patch_available:
            inputs_used["days_open"] = finding.days_open
            inputs_used["threshold_days"] = threshold
        return TreeOutcome(
            value="Monitor",
            path=["exploitation likelihood is Low", "not yet overdue, or no patch available → Monitor"],
            inputs_used=inputs_used,
        )

    # likelihood.value == "Unknown"
    inputs_used = {"exploitation_likelihood": "Unknown", "asset_internet_facing": finding.asset_internet_facing}
    if finding.asset_internet_facing and overdue:
        inputs_used["days_open"] = finding.days_open
        inputs_used["threshold_days"] = threshold
        return TreeOutcome(
            value="Immediate",
            path=[
                "exploitation likelihood unknown",
                f"asset is internet-facing and the finding is {finding.days_open - threshold} "
                f"days past the {threshold}-day remediation threshold → Immediate",
            ],
            inputs_used=inputs_used,
        )

    if overdue:
        inputs_used["days_open"] = finding.days_open
        inputs_used["threshold_days"] = threshold
        return TreeOutcome(
            value="Scheduled",
            path=[
                "exploitation likelihood unknown",
                f"finding exceeds the {threshold}-day remediation threshold → Scheduled",
            ],
            inputs_used=inputs_used,
        )

    inputs_used["days_open"] = finding.days_open
    inputs_used["threshold_days"] = threshold
    if finding.patch_available:
        inputs_used["patch_available"] = True
        return TreeOutcome(
            value="Scheduled",
            path=[
                "exploitation likelihood unknown",
                "a fix exists and should enter the next remediation cycle → Scheduled",
            ],
            inputs_used=inputs_used,
        )

    inputs_used["patch_available"] = finding.patch_available
    return TreeOutcome(
        value="Monitor",
        path=["exploitation likelihood unknown", "no exposure, SLA breach or patch → Monitor"],
        inputs_used=inputs_used,
    )


def evaluate(finding: NormalisedFinding) -> AbstractionResult:
    """Run all three trees for one finding."""

    likelihood = assess_exploitation_likelihood(finding)
    impact = assess_preliminary_impact(finding)
    urgency = assess_urgency(finding, likelihood)
    return AbstractionResult(
        exploitation_likelihood=likelihood,
        business_impact=impact,
        urgency=urgency,
    )
