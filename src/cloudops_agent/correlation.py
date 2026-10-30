"""Conservative, deterministic cross-source finding correlations."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import json

from cloudops_agent.models import Finding, SourceType


@dataclass(frozen=True)
class FindingRef:
    """A finding namespaced to one uploaded artifact in an analysis run."""

    artifact_id: str
    finding_id: str


@dataclass(frozen=True)
class EvidenceValue:
    """One exact evidence observation from a finding."""

    path: str
    value: str


@dataclass(frozen=True)
class Correlation:
    """One cautious, evidence-only relationship between findings."""

    correlation_id: str
    relationship_type: str
    finding_refs: tuple[FindingRef, FindingRef]
    supporting_evidence: tuple[EvidenceValue, ...]
    explanation: str
    limitations: tuple[str, ...]


_RELATIONSHIP = "action_overlap"
_ACTION = "iam:CreateAccessKey"
_EVENT_SOURCE = "iam.amazonaws.com"
_EVENT_NAME = "CreateAccessKey"
_LIMITATIONS = (
    "This correlation does not establish a shared AWS account, shared actor, "
    "policy attachment, authorization, or causation.",
)


def correlate_findings(
    artifacts: Iterable[tuple[str, Iterable[Finding]]],
) -> tuple[Correlation, ...]:
    """Correlate exact IAM CreateAccessKey evidence with a CloudTrail event.

    Each artifact is ``(artifact_id, findings)``. Repeated references with
    identical Finding records are deduplicated. If one reference maps to
    unequal records, that reference is marked conflicting and excluded.
    Artifact IDs must be non-empty strings; finding entries must be Findings.
    """
    records: dict[FindingRef, Finding] = {}
    conflicts: set[FindingRef] = set()
    for artifact_id, findings in artifacts:
        if not isinstance(artifact_id, str) or not artifact_id.strip():
            raise ValueError("artifact_id must be a non-empty string.")
        for finding in findings:
            if not isinstance(finding, Finding):
                raise TypeError("artifact findings must contain Finding records.")
            ref = FindingRef(artifact_id, finding.finding_id)
            previous = records.get(ref)
            if previous is None:
                records[ref] = finding
            elif previous != finding:
                conflicts.add(ref)

    iam_candidates: set[FindingRef] = set()
    trail_candidates: set[FindingRef] = set()
    for ref, finding in records.items():
        if ref in conflicts:
            continue
        evidence = finding.evidence
        if finding.source_type is SourceType.IAM:
            actions = evidence.get("matched_actions")
            if isinstance(actions, list) and _ACTION in actions:
                iam_candidates.add(ref)
        elif finding.source_type is SourceType.CLOUDTRAIL:
            event = evidence.get("event")
            if (
                isinstance(event, Mapping)
                and event.get("eventSource") == _EVENT_SOURCE
                and event.get("eventName") == _EVENT_NAME
            ):
                trail_candidates.add(ref)

    if len(iam_candidates) != 1 or len(trail_candidates) != 1:
        return ()

    iam_ref = next(iter(iam_candidates))
    trail_ref = next(iter(trail_candidates))
    supporting_evidence = (
        EvidenceValue("evidence.matched_actions", _ACTION),
        EvidenceValue("evidence.event.eventSource", _EVENT_SOURCE),
        EvidenceValue("evidence.event.eventName", _EVENT_NAME),
    )
    canonical_refs = [
        {"source": "IAM", "artifact_id": iam_ref.artifact_id, "finding_id": iam_ref.finding_id},
        {"source": "CloudTrail", "artifact_id": trail_ref.artifact_id, "finding_id": trail_ref.finding_id},
    ]
    canonical = json.dumps(
        {"relationship_type": _RELATIONSHIP, "finding_refs": canonical_refs},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    correlation_id = "corr." + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return (Correlation(
        correlation_id=correlation_id,
        relationship_type=_RELATIONSHIP,
        finding_refs=(iam_ref, trail_ref),
        supporting_evidence=supporting_evidence,
        explanation=(
            "The IAM finding and CloudTrail finding both reference the "
            "iam:CreateAccessKey operation type. This is an evidence overlap only."
        ),
        limitations=_LIMITATIONS,
    ),)
