"""Shared, validated data types for security findings."""

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum


class SourceType(str, Enum):
    """Input source category that produced a finding."""

    CLOUDTRAIL = "CloudTrail"
    IAM = "IAM"
    TERRAFORM = "Terraform"


class Severity(str, Enum):
    """Normalized severity levels shared by all analyzers."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


@dataclass(frozen=True)
class Finding:
    """One analyzer result with source evidence and a suggested next step.

    ``finding_id`` is supplied by the analyzer and should be stable and unique
    for the particular finding. Evidence keys and nested values are source-
    specific; this model deliberately does not impose a schema on them.
    """

    finding_id: str
    title: str
    source_type: SourceType
    severity: Severity
    description: str
    evidence: Mapping[str, object]
    remediation: str

    def __post_init__(self) -> None:
        for field_name in ("finding_id", "title", "description", "remediation"):
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string.")
            if not value.strip():
                raise ValueError(f"{field_name} must not be empty or whitespace-only.")

        try:
            source_type = SourceType(self.source_type)
        except (TypeError, ValueError) as exc:
            allowed = ", ".join(source.value for source in SourceType)
            raise ValueError(f"source_type must be one of: {allowed}.") from exc
        object.__setattr__(self, "source_type", source_type)

        try:
            severity = Severity(self.severity)
        except (TypeError, ValueError) as exc:
            allowed = ", ".join(severity.value for severity in Severity)
            raise ValueError(f"severity must be one of: {allowed}.") from exc
        object.__setattr__(self, "severity", severity)

        if not isinstance(self.evidence, Mapping):
            raise TypeError("evidence must be a mapping.")
        object.__setattr__(self, "evidence", _copy_evidence(self.evidence))


def _copy_evidence(value: object, path: str = "evidence") -> object:
    """Copy evidence containers and reject non-string keys at every map level."""
    if isinstance(value, Mapping):
        copied: dict[str, object] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise TypeError(
                    f"evidence mapping keys must be strings; found {key!r} at {path}."
                )
            copied[key] = _copy_evidence(nested_value, f"{path}.{key}")
        return copied
    if isinstance(value, list):
        return [_copy_evidence(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, tuple):
        return tuple(_copy_evidence(item, f"{path}[{index}]") for index, item in enumerate(value))
    return deepcopy(value)
