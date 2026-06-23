"""Source-format adapters.

Each parser knows one source format and produces NormalisedFinding
records. This is the only layer that knows field names, date formats
and source-specific quirks; nothing downstream should need to know
where a finding came from beyond `source_format` and
`absent_by_format`.
"""

from __future__ import annotations

import html
import re
from abc import ABC, abstractmethod
from datetime import date, datetime

from explainer.config import THRESHOLDS, cvss_score_to_band, risk_score_to_criticality
from explainer.models import NormalisedFinding

ISD_INTERNAL_VULNERABILITY_CATEGORY = "Internal Vulnerabilities"

ISD_ABSENT_FIELDS = frozenset(
    {
        "cvss_score",
        "exploit_available",
        "known_exploited",
        "attack_vector",
        "asset_id",
        "hostname",
    }
)


class BaseParser(ABC):
    """Common interface for source-format adapters."""

    source_format: str
    absent_by_format: frozenset[str]

    @abstractmethod
    def parse(self, raw) -> list[NormalisedFinding]:
        """Turn raw source data into normalised findings."""


class QualysJsonParser(BaseParser):
    """Parses the synthetic Qualys-style JSON scenarios."""

    source_format = "qualys_json"
    absent_by_format = frozenset()

    def parse(self, raw: dict) -> list[NormalisedFinding]:
        asset = raw.get("asset", {})
        cvss_score = raw.get("cvss_score")
        patch_age_days = self._patch_age_days(
            last_scan_date=raw.get("last_scan_date"),
            patch_release_date=raw.get("patch_release_date"),
        )

        finding = NormalisedFinding(
            vulnerability_id=raw.get("cve_id"),
            additional_cve_ids=list(raw.get("additional_cve_ids", [])),
            title=raw.get("title"),
            severity=raw.get("severity"),
            severity_band=cvss_score_to_band(cvss_score),
            cvss_score=cvss_score,
            exploit_available=raw.get("exploit_available"),
            known_exploited=raw.get("known_exploited"),
            attack_vector=raw.get("attack_vector"),
            patch_available=raw.get("patch_available"),
            patch_age_days=patch_age_days,
            days_open=raw.get("days_open"),
            threshold_days=raw.get("threshold_days"),
            solution_text=raw.get("solution"),
            asset_id=asset.get("id"),
            hostname=asset.get("hostname"),
            operating_system=asset.get("operating_system"),
            asset_environment=asset.get("environment"),
            asset_criticality=risk_score_to_criticality(asset.get("risk_score")),
            asset_internet_facing=asset.get("internet_facing"),
            status=raw.get("status"),
            last_scan_date=raw.get("last_scan_date"),
            source_format=self.source_format,
            absent_by_format=self.absent_by_format,
        )
        return [finding]

    @staticmethod
    def _patch_age_days(last_scan_date: str | None, patch_release_date: str | None) -> int | None:
        if last_scan_date is None or patch_release_date is None:
            return None
        scanned = date.fromisoformat(last_scan_date)
        released = date.fromisoformat(patch_release_date)
        return (scanned - released).days


class ISDCsvParser(BaseParser):
    """Parses the Accenture ISD CSV export.

    Only rows where Issue Category is "Internal Vulnerabilities" are
    kept; out-of-compliance findings are a different explanation genre
    and are out of scope (see ADR-0006).
    """

    source_format = "isd_csv"
    absent_by_format = ISD_ABSENT_FIELDS

    def parse(self, raw: list[dict]) -> list[NormalisedFinding]:
        return [
            self._parse_row(row)
            for row in raw
            if row.get("Issue Category") == ISD_INTERNAL_VULNERABILITY_CATEGORY
        ]

    def _parse_row(self, row: dict) -> NormalisedFinding:
        vulnerability_id, additional_cve_ids = self._split_cve_ids(row.get("CVE ID", ""))
        asset_environment = self._clean(row.get("Asset Environment"))

        return NormalisedFinding(
            vulnerability_id=vulnerability_id,
            additional_cve_ids=additional_cve_ids,
            title=self._clean(row.get("Issue Title")),
            severity=None,
            severity_band=self._clean(row.get("Severity")),
            cvss_score=None,
            exploit_available=None,
            known_exploited=None,
            attack_vector=None,
            patch_available=self._yes_no(row.get("Patchable")),
            patch_age_days=self._to_int(row.get("CVE Age")),
            days_open=self._to_int(row.get("Age")),
            threshold_days=self._to_int(row.get("Threshold")),
            solution_text=self._strip_html(row.get("Solution")),
            asset_id=self._clean(row.get("Asset Id")),
            hostname=None,
            operating_system=self._lower(row.get("Operating System")),
            asset_environment=asset_environment,
            asset_criticality=self._criticality_from_environment(asset_environment),
            asset_internet_facing=self._yes_no(row.get("Remote Discovery")),
            status=self._clean(row.get("Issue Status")),
            last_scan_date=self._to_iso_date(row.get("Last Scan Date")),
            source_format=self.source_format,
            absent_by_format=self.absent_by_format,
        )

    @staticmethod
    def _clean(value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @classmethod
    def _lower(cls, value: str | None) -> str | None:
        cleaned = cls._clean(value)
        return cleaned.lower() if cleaned is not None else None

    @classmethod
    def _split_cve_ids(cls, value: str | None) -> tuple[str | None, list[str]]:
        if not value or not value.strip():
            return None, []
        ids = [part.strip() for part in value.split(",") if part.strip()]
        if not ids:
            return None, []
        return ids[0], ids[1:]

    @classmethod
    def _yes_no(cls, value: str | None) -> bool | None:
        cleaned = cls._clean(value)
        if cleaned is None:
            return None
        if cleaned.lower() == "yes":
            return True
        if cleaned.lower() == "no":
            return False
        return None

    @classmethod
    def _to_int(cls, value: str | None) -> int | None:
        cleaned = cls._clean(value)
        if cleaned is None:
            return None
        try:
            return int(float(cleaned))
        except ValueError:
            return None

    @classmethod
    def _to_iso_date(cls, value: str | None) -> str | None:
        cleaned = cls._clean(value)
        if cleaned is None:
            return None
        return datetime.strptime(cleaned, "%m/%d/%Y").date().isoformat()

    @staticmethod
    def _criticality_from_environment(asset_environment: str | None) -> str | None:
        if asset_environment is None:
            return None
        mapping = THRESHOLDS["criticality_from_environment"]
        return mapping.get(asset_environment.strip().lower())

    @classmethod
    def _strip_html(cls, value: str | None) -> str | None:
        cleaned = cls._clean(value)
        if cleaned is None:
            return None
        without_tags = re.sub(r"<[^>]+>", "", cleaned)
        without_escaped_newlines = without_tags.replace("\\n", " ").replace("\\r", " ")
        unescaped = html.unescape(without_escaped_newlines)
        return re.sub(r"\s+", " ", unescaped).strip()


PARSERS: dict[str, BaseParser] = {
    "qualys_json": QualysJsonParser(),
    "isd_csv": ISDCsvParser(),
}
