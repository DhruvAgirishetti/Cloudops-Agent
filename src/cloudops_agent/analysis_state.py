"""Small helpers for associating UI analysis results with uploaded content."""

import hashlib
from collections.abc import MutableMapping, Set

from cloudops_agent.models import Finding


def analysis_result_key(analyzer_name: str, file_index: int, content: bytes) -> str:
    """Return a stable UI key tied to one upload position and its exact bytes."""
    content_hash = hashlib.sha256(content).hexdigest()
    return f"{analyzer_name}-analysis-result-{file_index}-{content_hash}"


def clear_inactive_analysis_results(
    session_state: MutableMapping[str, object],
    analyzer_name: str,
    active_result_keys: Set[str],
) -> None:
    """Remove saved results for uploads no longer present in the current UI."""
    prefix = f"{analyzer_name}-analysis-result-"
    for key in list(session_state):
        if key.startswith(prefix) and key not in active_result_keys:
            del session_state[key]


def current_finding_artifacts(
    session_state: MutableMapping[str, object],
    active_results: dict[str, Set[str]],
) -> list[tuple[str, list[Finding]]]:
    """Return successful findings for currently uploaded artifacts only.

    The existing result key is used as the artifact ID: it includes analyzer,
    upload position, and a content hash, so distinct uploads remain distinct.
    Results containing errors or malformed finding collections are excluded.
    """
    artifacts: list[tuple[str, list[Finding]]] = []
    for analyzer_name, active_keys in active_results.items():
        for result_key in sorted(active_keys):
            result = session_state.get(result_key)
            if not isinstance(result, dict) or "error" in result:
                continue
            findings = result.get("findings")
            if not isinstance(findings, list) or any(
                not isinstance(finding, Finding) for finding in findings
            ):
                continue
            artifacts.append((result_key, findings))
    return artifacts
