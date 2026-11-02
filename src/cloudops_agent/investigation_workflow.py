"""Small Streamlit-facing helpers for scoped AI investigation actions."""

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping, MutableMapping, Sequence

from cloudops_agent.correlation import Correlation, FindingRef
from cloudops_agent.investigation_input import BuiltInvestigationInput, build_investigation_input
from cloudops_agent.meta_provider import (
    MetaClient,
    MetaClientError,
    MetaConfigurationError,
    MetaEmptyResponseError,
    MetaInputError,
    MetaOutputValidationError,
    MetaProvider,
    MetaProviderError,
    MetaRefusalError,
    MetaResponseExtractionError,
    create_live_meta_client,
)
from cloudops_agent.models import Finding


AI_RESULT_PREFIX = "ai-investigation-result-"
FINDING_REQUEST = "Explain this finding, its evidence and limitations, and provide advisory next steps."
CORRELATION_REQUEST = "Explain the evidence overlap, its limitations, and advisory next steps."


def finding_investigation_key(reference: FindingRef) -> str:
    """Return a request-result key bound to the complete artifact-scoped reference."""
    if not isinstance(reference, FindingRef):
        raise TypeError("reference must be a FindingRef.")
    identity = {
        "kind": "finding",
        "artifact_id": reference.artifact_id,
        "finding_id": reference.finding_id,
    }
    return _key_for_identity(identity)


def correlation_investigation_key(correlation: Correlation) -> str:
    """Return a result key bound to the correlation and both artifact-scoped endpoints."""
    if not isinstance(correlation, Correlation):
        raise TypeError("correlation must be a Correlation.")
    identity = {
        "kind": "correlation",
        "correlation_id": correlation.correlation_id,
        "finding_refs": [
            {"artifact_id": ref.artifact_id, "finding_id": ref.finding_id}
            for ref in correlation.finding_refs
        ],
    }
    return _key_for_identity(identity)


def active_investigation_result_keys(
    artifacts: Iterable[tuple[str, Sequence[Finding]]],
    correlations: Iterable[Correlation],
) -> set[str]:
    keys: set[str] = set()
    for artifact_id, findings in artifacts:
        for finding in findings:
            keys.add(finding_investigation_key(FindingRef(artifact_id, finding.finding_id)))
    for correlation in correlations:
        keys.add(correlation_investigation_key(correlation))
    return keys


def clear_inactive_investigation_results(
    session_state: MutableMapping[str, object],
    active_result_keys: set[str],
) -> None:
    """Drop stored AI records whose exact finding/correlation scope is no longer current."""
    for key in list(session_state):
        if key.startswith(AI_RESULT_PREFIX) and key not in active_result_keys:
            del session_state[key]


def build_finding_investigation(
    reference: FindingRef,
    *,
    artifacts: Iterable[tuple[str, Sequence[Finding]]],
    correlations: Iterable[Correlation],
    artifact_limitations: Mapping[str, Sequence[str]] | None = None,
) -> BuiltInvestigationInput:
    """Build a finding-scoped request through the approved input builder."""
    return build_investigation_input(
        user_request=FINDING_REQUEST,
        scope=reference,
        artifacts=artifacts,
        correlations=correlations,
        artifact_limitations=artifact_limitations,
    )


def build_correlation_investigation(
    correlation: Correlation,
    *,
    artifacts: Iterable[tuple[str, Sequence[Finding]]],
    correlations: Iterable[Correlation],
) -> BuiltInvestigationInput:
    """Build a correlation request; the input builder resolves its two endpoints."""
    return build_investigation_input(
        user_request=CORRELATION_REQUEST,
        scope=correlation,
        artifacts=artifacts,
        correlations=correlations,
    )


def execute_investigation_action(
    session_state: MutableMapping[str, object],
    result_key: str,
    built_input: BuiltInvestigationInput,
    *,
    requested: bool,
    label: str,
    client_factory: Callable[[], MetaClient] = create_live_meta_client,
) -> None:
    """Run once only when explicitly requested and store only safe result records."""
    if not requested:
        return
    try:
        provider = MetaProvider(client_factory())
        output = provider.investigate(built_input)
    except MetaProviderError as error:
        session_state[result_key] = {
            "status": "error",
            "label": label,
            "message": _safe_error_message(error),
        }
    except Exception:
        session_state[result_key] = {
            "status": "error",
            "label": label,
            "message": "AI investigation could not be completed.",
        }
    else:
        session_state[result_key] = {
            "status": "success",
            "label": label,
            "output": output,
        }


def _safe_error_message(error: MetaProviderError) -> str:
    if isinstance(error, MetaConfigurationError):
        return "AI investigation is not configured. Set MODEL_API_KEY in the environment before using live AI investigation."
    if isinstance(error, MetaInputError):
        return "The selected investigation context is no longer valid. Refresh the analysis and try again."
    if isinstance(error, MetaRefusalError):
        return "The AI provider declined to provide an investigation for this request."
    if isinstance(error, MetaClientError):
        return "The AI provider request failed. Check the provider setup and try again."
    if isinstance(error, (MetaEmptyResponseError, MetaResponseExtractionError)):
        return "The AI provider returned no usable response. Try again later."
    if isinstance(error, MetaOutputValidationError):
        return "The AI response did not pass validation and was not displayed."
    return "AI investigation could not be completed."


def _key_for_identity(identity: dict[str, object]) -> str:
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return AI_RESULT_PREFIX + hashlib.sha256(encoded).hexdigest()
