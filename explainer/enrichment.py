"""Optional CMDB enrichment: join a finding to its asset on asset_id.

Sits between ingestion and abstraction. When a finding's asset_id resolves
in the CMDB asset lookup, the asset's exposure and criticality are written
onto the finding via dataclasses.replace. When it does not resolve (no key,
or key absent from the lookup), the finding is returned unchanged. This is
the graceful-degradation case that mirrors the real ISD export, which
carries no asset identifier.
"""

from __future__ import annotations

import csv
import dataclasses
from pathlib import Path

from explainer.models import NormalisedFinding


def load_asset_lookup(path: Path) -> dict[str, dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return {row["asset_id"].strip(): row
                for row in csv.DictReader(f) if row.get("asset_id", "").strip()}


def load_identity_lookup(path: Path) -> dict[str, dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return {row["identity_email"].strip().lower(): row
                for row in csv.DictReader(f) if row.get("identity_email", "").strip()}


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"true", "yes", "1"}


def _exposure_to_internet_facing(asset: dict) -> bool:
    return (
        (asset.get("asset_exposure") or "").strip().lower() == "external"
        or _truthy(asset.get("asset_is_on_external_dns"))
        or _truthy(asset.get("asset_is_extranet_exposed"))
    )


def enrich(finding: NormalisedFinding, asset_lookup: dict[str, dict]) -> NormalisedFinding:
    """Return finding with CMDB-derived fields, or unchanged if no match."""
    if finding.asset_id is None:
        return finding
    asset = asset_lookup.get(finding.asset_id.strip())
    if asset is None:
        return finding

    internet_facing = _exposure_to_internet_facing(asset)
    criticality = "High" if _truthy(asset.get("asset_is_business_critical")) else finding.asset_criticality

    # asset_environment is NOT overwritten. The CMDB environment field
    # is a region/subsidiary code, not a production/staging lifecycle, so the
    # ISD Asset Environment must continue to drive the impact tree.
    return dataclasses.replace(
        finding,
        asset_internet_facing=internet_facing,
        asset_criticality=criticality,
    )
