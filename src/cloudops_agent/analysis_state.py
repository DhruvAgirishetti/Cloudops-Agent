"""Small helpers for associating UI analysis results with uploaded content."""

import hashlib
from collections.abc import MutableMapping, Set


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
