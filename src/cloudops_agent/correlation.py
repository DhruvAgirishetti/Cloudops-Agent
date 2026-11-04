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
    finding_refs: tuple[FindingRef, ...]
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
_NETWORK_LIMITATIONS = (
    "The Terraform evidence is a configuration-pattern overlap and does not identify the deployed security group. "
    "This correlation does not establish a shared AWS account, shared actor, causation, policy attachment, or authorization.",
)


def correlate_findings(
    artifacts: Iterable[tuple[str, Iterable[Finding]]],
) -> tuple[Correlation, ...]:
    """Correlate exact IAM/CloudTrail operation evidence and network patterns.

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

    result: list[Correlation] = []
    if len(iam_candidates) == 1 and len(trail_candidates) == 1:
        iam_ref, trail_ref = next(iter(iam_candidates)), next(iter(trail_candidates))
        result.append(_make_correlation(
            _RELATIONSHIP,
            (iam_ref, trail_ref),
            (
                EvidenceValue("evidence.matched_actions", _ACTION),
                EvidenceValue("evidence.event.eventSource", _EVENT_SOURCE),
                EvidenceValue("evidence.event.eventName", _EVENT_NAME),
            ),
            "The IAM finding and CloudTrail finding both reference the iam:CreateAccessKey operation type. This is an evidence overlap only.",
            _LIMITATIONS,
        ))

    network_iam: set[FindingRef] = set()
    network_trail: dict[FindingRef, set[tuple[int, str]]] = {}
    network_tf: dict[FindingRef, set[tuple[int, str]]] = {}
    for ref, finding in records.items():
        if ref in conflicts:
            continue
        if finding.source_type is SourceType.IAM and _has_exact_iam_action(finding, "ec2:AuthorizeSecurityGroupIngress"):
            network_iam.add(ref)
        elif finding.source_type is SourceType.CLOUDTRAIL:
            pattern = _cloudtrail_ingress_pattern(finding)
            if pattern:
                network_trail[ref] = pattern
        elif finding.source_type is SourceType.TERRAFORM:
            pattern = _terraform_ingress_pattern(finding)
            if pattern:
                network_tf[ref] = pattern

    if len(network_iam) == len(network_trail) == len(network_tf) == 1:
        iam_ref = next(iter(network_iam))
        trail_ref, trail_patterns = next(iter(network_trail.items()))
        tf_ref, tf_patterns = next(iter(network_tf.items()))
        overlap = sorted(trail_patterns & tf_patterns)
        if overlap:
            port, cidr = overlap[0]
            trail_finding = records[trail_ref]
            terraform_finding = records[tf_ref]
            permission_index, port_index, cidr_index = _cloudtrail_pattern_location(
                trail_finding, port, cidr,
            )
            configured = terraform_finding.evidence["configured_values"]
            terraform_cidr_index = configured["public_cidrs"].index(cidr)
            terraform_evidence = [
                EvidenceValue("evidence.configured_values.protocol", str(configured["protocol"])),
            ]
            if configured["protocol"] != "-1":
                terraform_evidence.extend((
                    EvidenceValue("evidence.configured_values.from_port", str(configured["from_port"])),
                    EvidenceValue("evidence.configured_values.to_port", str(configured["to_port"])),
                ))
            terraform_evidence.append(
                EvidenceValue(f"evidence.configured_values.public_cidrs[{terraform_cidr_index}]", cidr),
            )
            result.append(_make_correlation(
                "configuration_pattern_overlap",
                (iam_ref, trail_ref, tf_ref),
                (
                    EvidenceValue("evidence.Action", "ec2:AuthorizeSecurityGroupIngress"),
                    EvidenceValue("evidence.event.eventName", "AuthorizeSecurityGroupIngress"),
                    EvidenceValue(f"evidence.matched_permissions[{permission_index}].protocol", "tcp"),
                    EvidenceValue(f"evidence.matched_permissions[{permission_index}].admin_ports[{port_index}]", str(port)),
                    EvidenceValue(f"evidence.matched_permissions[{permission_index}].public_cidrs[{cidr_index}]", cidr),
                    *terraform_evidence,
                ),
                "This is a configuration-pattern overlap: the IAM finding names the exact ingress-change action, while the CloudTrail event and Terraform finding share a public TCP SSH/RDP pattern. The Terraform resource is not identified as the resource changed by the event.",
                _NETWORK_LIMITATIONS,
            ))
    return tuple(sorted(result, key=lambda item: item.correlation_id))


def _has_exact_iam_action(finding: Finding, action: str) -> bool:
    evidence = finding.evidence
    raw = evidence.get("Action")
    raw_actions = [raw] if isinstance(raw, str) else raw
    return (
        evidence.get("Effect") == "Allow"
        and isinstance(raw_actions, list)
        and action in raw_actions
        and not any("*" in item or "?" in item for item in raw_actions if isinstance(item, str))
        and isinstance(evidence.get("matched_actions"), list)
        and action in evidence["matched_actions"]
    )


def _cloudtrail_ingress_pattern(finding: Finding) -> set[tuple[int, str]]:
    evidence = finding.evidence
    event = evidence.get("event")
    permissions = evidence.get("matched_permissions")
    if (
        evidence.get("rule_id") != "ec2-authorize-security-group-ingress-public-admin"
        or not isinstance(event, Mapping)
        or event.get("eventSource") != "ec2.amazonaws.com"
        or event.get("eventName") != "AuthorizeSecurityGroupIngress"
        or "errorCode" in event
        or not isinstance(permissions, list)
    ):
        return set()
    return {
        (port, cidr)
        for permission in permissions if isinstance(permission, Mapping)
        if permission.get("protocol") == "tcp"
        for port in permission.get("admin_ports", []) if port in {22, 3389}
        for cidr in permission.get("public_cidrs", []) if cidr in {"0.0.0.0/0", "::/0"}
    }


def _terraform_ingress_pattern(finding: Finding) -> set[tuple[int, str]]:
    evidence = finding.evidence
    configured = evidence.get("configured_values")
    if evidence.get("rule_id") != "security-group-public-admin-ingress" or not isinstance(configured, Mapping):
        return set()
    protocol = configured.get("protocol")
    cidrs = configured.get("public_cidrs")
    if protocol not in {"tcp", "TCP", "6", "-1"} or not isinstance(cidrs, list):
        return set()
    if protocol == "-1":
        return {
            (port, cidr) for port in {22, 3389}
            for cidr in cidrs if cidr in {"0.0.0.0/0", "::/0"}
        }
    start, end = configured.get("from_port"), configured.get("to_port")
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in (start, end)):
        return set()
    return {
        (port, cidr) for port in {22, 3389} if start <= port <= end
        for cidr in cidrs if cidr in {"0.0.0.0/0", "::/0"}
    }


def _cloudtrail_pattern_location(finding: Finding, port: int, cidr: str) -> tuple[int, int, int]:
    permissions = finding.evidence["matched_permissions"]
    for permission_index, permission in enumerate(permissions):
        if permission.get("protocol") != "tcp":
            continue
        if port not in permission.get("admin_ports", ()) or cidr not in permission.get("public_cidrs", ()):
            continue
        return (
            permission_index,
            permission["admin_ports"].index(port),
            permission["public_cidrs"].index(cidr),
        )
    raise ValueError("Matched CloudTrail pattern has no supporting evidence location.")


def _make_correlation(
    relationship: str,
    refs: tuple[FindingRef, ...],
    evidence: tuple[EvidenceValue, ...],
    explanation: str,
    limitations: tuple[str, ...],
) -> Correlation:
    source_names = {
        SourceType.IAM: "IAM", SourceType.CLOUDTRAIL: "CloudTrail", SourceType.TERRAFORM: "Terraform",
    }
    canonical_refs = [
        {"source": source_names[source], "artifact_id": ref.artifact_id, "finding_id": ref.finding_id}
        for source, ref in zip((SourceType.IAM, SourceType.CLOUDTRAIL, SourceType.TERRAFORM), refs)
    ]
    canonical = json.dumps(
        {"relationship_type": relationship, "finding_refs": canonical_refs},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return Correlation(
        correlation_id="corr." + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        relationship_type=relationship, finding_refs=refs, supporting_evidence=evidence,
        explanation=explanation, limitations=limitations,
    )
