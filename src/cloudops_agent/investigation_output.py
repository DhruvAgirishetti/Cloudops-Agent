"""Strict structural and request-scoped citation validation for AI output."""

from dataclasses import dataclass
import copy
import json
from typing import Literal

from cloudops_agent.investigation_input import InvestigationReferences


SCHEMA_VERSION = "1"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_SUMMARY_CHARS = 2_000
MAX_CLAIM_CHARS = 3_000
MAX_LIMITATION_CHARS = 2_000
MAX_ACTION_CHARS = 1_500
MAX_RATIONALE_CHARS = 3_000
MAX_UNCERTAINTY_NOTE_CHARS = 500
MAX_OBSERVATIONS = 30
MIN_RECOMMENDATIONS = 1
MAX_RECOMMENDATIONS = 3
MAX_LIMITATIONS = 20
MAX_CITATIONS_PER_ITEM = 3


def _citation_schema() -> dict[str, object]:
    return {
        "type": "array",
        "minItems": 1,
        "maxItems": MAX_CITATIONS_PER_ITEM,
        "items": {"type": "string", "minLength": 1},
    }


def _uncertainty_schema() -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            "present": {"type": "boolean"},
            "note": {"anyOf": [{"type": "string", "minLength": 1, "maxLength": MAX_UNCERTAINTY_NOTE_CHARS}, {"type": "null"}]},
        },
        "required": ["present", "note"],
        "additionalProperties": False,
    }


# Canonical constrained-decoding schema for providers that support JSON Schema.
# The validator below remains authoritative for request-scoped citation checks.
_OUTPUT_JSON_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "schema_version": {"type": "string", "enum": [SCHEMA_VERSION]},
        "summary": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "minLength": 1, "maxLength": MAX_SUMMARY_CHARS},
                "references": _citation_schema(),
            },
            "required": ["text", "references"],
            "additionalProperties": False,
        },
        "observations": {
            "type": "array",
            "maxItems": MAX_OBSERVATIONS,
            "items": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string", "minLength": 1, "maxLength": MAX_CLAIM_CHARS},
                    "basis": {"type": "string", "enum": ["direct_evidence", "interpretation"]},
                    "references": _citation_schema(),
                    "uncertainty": _uncertainty_schema(),
                },
                "required": ["claim", "basis", "references", "uncertainty"],
                "additionalProperties": False,
            },
        },
        "limitations": {
            "type": "array",
            "maxItems": MAX_LIMITATIONS,
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "minLength": 1, "maxLength": MAX_LIMITATION_CHARS},
                    "references": _citation_schema(),
                },
                "required": ["text", "references"],
                "additionalProperties": False,
            },
        },
        "recommendations": {
            "type": "array",
            "minItems": MIN_RECOMMENDATIONS,
            "maxItems": MAX_RECOMMENDATIONS,
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["investigation", "remediation"]},
                    "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                    "action": {"type": "string", "minLength": 1, "maxLength": MAX_ACTION_CHARS},
                    "rationale": {"type": "string", "minLength": 1, "maxLength": MAX_RATIONALE_CHARS},
                    "references": _citation_schema(),
                    "uncertainty": _uncertainty_schema(),
                },
                "required": ["type", "priority", "action", "rationale", "references", "uncertainty"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["schema_version", "summary", "observations", "limitations", "recommendations"],
    "additionalProperties": False,
}


def investigation_output_json_schema() -> dict[str, object]:
    """Return a fresh copy of the canonical output schema for provider requests."""
    return copy.deepcopy(_OUTPUT_JSON_SCHEMA)

ObservationBasis = Literal["direct_evidence", "interpretation"]
RecommendationType = Literal["investigation", "remediation"]
RecommendationPriority = Literal["high", "medium", "low"]


class InvestigationOutputValidationError(ValueError):
    """Raised when provider output fails the deterministic output contract."""


@dataclass(frozen=True)
class Uncertainty:
    present: bool
    note: str | None


@dataclass(frozen=True)
class CitedText:
    text: str
    references: tuple[str, ...]


@dataclass(frozen=True)
class Observation:
    claim: str
    basis: ObservationBasis
    references: tuple[str, ...]
    uncertainty: Uncertainty


@dataclass(frozen=True)
class Recommendation:
    type: RecommendationType
    priority: RecommendationPriority
    action: str
    rationale: str
    references: tuple[str, ...]
    uncertainty: Uncertainty


@dataclass(frozen=True)
class InvestigationOutput:
    schema_version: str
    summary: CitedText
    observations: tuple[Observation, ...]
    limitations: tuple[CitedText, ...]
    recommendations: tuple[Recommendation, ...]


def validate_investigation_output(
    raw_output: str | bytes,
    references: InvestigationReferences,
) -> InvestigationOutput:
    """Parse and validate a response against one request's opaque reference map.

    Structural validation and citation existence do not establish that a claim
    is semantically supported by the cited evidence.
    """
    document = _parse_json(raw_output)
    _validate_reference_scope(references)
    _expect_keys(document, {"schema_version", "summary", "observations", "limitations", "recommendations"}, "output")

    if document["schema_version"] != SCHEMA_VERSION:
        _fail("output.schema_version is unsupported.")

    allowed_refs = set(references.findings) | set(references.correlations)
    summary_data = document["summary"]
    _expect_keys(summary_data, {"text", "references"}, "summary")
    summary = CitedText(
        text=_string(summary_data["text"], "summary.text", MAX_SUMMARY_CHARS),
        references=_citations(summary_data["references"], "summary.references", allowed_refs),
    )

    observation_data = _list(document["observations"], "observations", MAX_OBSERVATIONS)
    observations: list[Observation] = []
    for index, item in enumerate(observation_data):
        path = f"observations[{index}]"
        _expect_keys(item, {"claim", "basis", "references", "uncertainty"}, path)
        basis = item["basis"]
        if not isinstance(basis, str) or basis not in {"direct_evidence", "interpretation"}:
            _fail(f"{path}.basis is unsupported.")
        observations.append(Observation(
            claim=_string(item["claim"], f"{path}.claim", MAX_CLAIM_CHARS),
            basis=basis,
            references=_citations(item["references"], f"{path}.references", allowed_refs),
            uncertainty=_uncertainty(item["uncertainty"], f"{path}.uncertainty"),
        ))

    limitation_data = _list(document["limitations"], "limitations", MAX_LIMITATIONS)
    limitations: list[CitedText] = []
    for index, item in enumerate(limitation_data):
        path = f"limitations[{index}]"
        _expect_keys(item, {"text", "references"}, path)
        limitations.append(CitedText(
            text=_string(item["text"], f"{path}.text", MAX_LIMITATION_CHARS),
            references=_citations(item["references"], f"{path}.references", allowed_refs),
        ))

    recommendation_data = _list(
        document["recommendations"], "recommendations", MAX_RECOMMENDATIONS,
    )
    if len(recommendation_data) < MIN_RECOMMENDATIONS:
        _fail("recommendations must contain at least one item.")
    recommendations: list[Recommendation] = []
    for index, item in enumerate(recommendation_data):
        path = f"recommendations[{index}]"
        _expect_keys(
            item,
            {"type", "priority", "action", "rationale", "references", "uncertainty"},
            path,
        )
        recommendation_type = item["type"]
        if not isinstance(recommendation_type, str) or recommendation_type not in {"investigation", "remediation"}:
            _fail(f"{path}.type is unsupported.")
        priority = item["priority"]
        if not isinstance(priority, str) or priority not in {"high", "medium", "low"}:
            _fail(f"{path}.priority is unsupported.")
        recommendations.append(Recommendation(
            type=recommendation_type,
            priority=priority,
            action=_string(item["action"], f"{path}.action", MAX_ACTION_CHARS),
            rationale=_string(item["rationale"], f"{path}.rationale", MAX_RATIONALE_CHARS),
            references=_citations(item["references"], f"{path}.references", allowed_refs),
            uncertainty=_uncertainty(item["uncertainty"], f"{path}.uncertainty"),
        ))

    return InvestigationOutput(
        schema_version=SCHEMA_VERSION,
        summary=summary,
        observations=tuple(observations),
        limitations=tuple(limitations),
        recommendations=tuple(recommendations),
    )


def _parse_json(raw_output: str | bytes) -> dict[str, object]:
    if isinstance(raw_output, bytes):
        if len(raw_output) > MAX_RESPONSE_BYTES:
            _fail("Response exceeds the maximum allowed size.")
        try:
            raw_output = raw_output.decode("utf-8")
        except UnicodeDecodeError:
            _fail("Response must be UTF-8 JSON.")
    elif isinstance(raw_output, str):
        try:
            if len(raw_output.encode("utf-8")) > MAX_RESPONSE_BYTES:
                _fail("Response exceeds the maximum allowed size.")
        except UnicodeEncodeError:
            _fail("Response must be valid UTF-8 JSON.")
    else:
        _fail("Response must be a JSON string or UTF-8 bytes.")

    try:
        parsed = json.loads(
            raw_output,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: _fail("Response contains an invalid JSON number."),
        )
    except InvestigationOutputValidationError:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError):
        _fail("Response is not valid JSON.")
    if not isinstance(parsed, dict):
        _fail("Response top level must be an object.")
    return parsed


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("Response contains a duplicate object property.")
        result[key] = value
    return result


def _validate_reference_scope(references: InvestigationReferences) -> None:
    referenced_artifacts = {
        ref.artifact_id for ref in references.findings.values()
    }
    if set(references.artifacts.values()) != referenced_artifacts:
        _fail("Request reference map contains an unrelated artifact.")
    if references.scope_kind == "finding":
        if (
            references.target_ref not in references.findings
            or set(references.findings) != {references.target_ref}
            or references.correlations
            or references.correlation_findings
        ):
            _fail("Request reference map has an invalid finding scope.")
    elif references.scope_kind == "correlation":
        endpoints = references.correlation_findings.get(references.target_ref)
        if (
            references.target_ref not in references.correlations
            or set(references.correlations) != {references.target_ref}
            or endpoints is None
            or len(endpoints) != 2
            or len(set(endpoints)) != 2
            or set(references.findings) != set(endpoints)
        ):
            _fail("Request reference map has an invalid correlation scope.")
    else:
        _fail("Request reference map has an unsupported scope.")


def _expect_keys(value: object, expected: set[str], path: str) -> None:
    if not isinstance(value, dict):
        _fail(f"{path} must be an object.")
    actual = set(value)
    missing = expected - actual
    extra = actual - expected
    if missing:
        _fail(f"{path} is missing required properties.")
    if extra:
        _fail(f"{path} contains unexpected properties.")


def _string(value: object, path: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{path} must be a non-empty string.")
    if len(value) > maximum:
        _fail(f"{path} exceeds the maximum length.")
    return value


def _list(value: object, path: str, maximum: int) -> list[object]:
    if not isinstance(value, list):
        _fail(f"{path} must be a list.")
    if len(value) > maximum:
        _fail(f"{path} exceeds the maximum number of entries.")
    return value


def _citations(value: object, path: str, allowed: set[str]) -> tuple[str, ...]:
    citations = _list(value, path, MAX_CITATIONS_PER_ITEM)
    if not citations:
        _fail(f"{path} must cite at least one supplied finding or correlation.")
    if any(not isinstance(citation, str) for citation in citations):
        _fail(f"{path} entries must be opaque reference strings.")
    if len(set(citations)) != len(citations):
        _fail(f"{path} must not repeat citations.")
    if any(citation not in allowed for citation in citations):
        _fail(f"{path} contains an unknown or out-of-scope reference.")
    return tuple(citations)


def _uncertainty(value: object, path: str) -> Uncertainty:
    _expect_keys(value, {"present", "note"}, path)
    present = value["present"]
    note = value["note"]
    if type(present) is not bool:
        _fail(f"{path}.present must be a boolean.")
    if present:
        if not isinstance(note, str) or not note.strip():
            _fail(f"{path}.note must explain the uncertainty when present is true.")
        if len(note) > MAX_UNCERTAINTY_NOTE_CHARS:
            _fail(f"{path}.note exceeds the maximum length.")
        return Uncertainty(True, note)
    if note is not None:
        _fail(f"{path}.note must be null when present is false.")
    return Uncertainty(False, None)


def _fail(message: str) -> None:
    raise InvestigationOutputValidationError(message)
