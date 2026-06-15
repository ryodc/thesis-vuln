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

BUSINESS_IMPACT_MATRIX = {
    "Critical": {"High": "Critical", "Medium": "High", "Low": "High"},
    "High": {"High": "High", "Medium": "Medium", "Low": "Medium"},
    "Medium": {"High": "Medium", "Medium": "Low", "Low": "Low"},
    "Low": {"High": "Low", "Medium": "Low", "Low": "Low"},
}


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


def assess_business_impact(finding: NormalisedFinding) -> TreeOutcome:
    """Tree 2: business impact from severity and asset criticality.

    Falls back to the scanner's categorical severity band when no
    numeric CVSS score is available, rather than fabricating one
    (ADR-0003).
    """

    path: list[str] = []
    inputs_used: dict[str, object] = {"cvss_score": finding.cvss_score}

    score_band = cvss_score_to_band(finding.cvss_score)
    if score_band is not None:
        path.append(f"score band {score_band} from CVSS {finding.cvss_score}")
    else:
        inputs_used["severity_band"] = finding.severity_band
        score_band = finding.severity_band
        if score_band is not None:
            path.append(f"no numeric CVSS score; using scanner severity band '{score_band}'")

    if score_band is None:
        path.append("neither a numeric CVSS score nor a scanner severity band was provided")
        return TreeOutcome(value="Unknown", path=path, inputs_used=inputs_used)

    inputs_used["asset_criticality"] = finding.asset_criticality
    if finding.asset_criticality is None:
        path.append("asset criticality not provided")
        return TreeOutcome(value="Unknown", path=path, inputs_used=inputs_used)

    impact = BUSINESS_IMPACT_MATRIX[score_band][finding.asset_criticality]
    path.append(
        f"severity band {score_band} × asset criticality {finding.asset_criticality} → {impact}"
    )
    return TreeOutcome(value=impact, path=path, inputs_used=inputs_used)


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
    impact = assess_business_impact(finding)
    urgency = assess_urgency(finding, likelihood)
    return AbstractionResult(
        exploitation_likelihood=likelihood,
        business_impact=impact,
        urgency=urgency,
    )
