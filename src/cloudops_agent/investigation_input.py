"""Build a minimal, provider-independent, request-scoped investigation payload."""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import re
import secrets
from types import MappingProxyType

from cloudops_agent.correlation import Correlation, EvidenceValue, FindingRef
from cloudops_agent.models import Finding, SourceType


SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class InvestigationReferences:
    """Private request-local maps used to translate opaque response citations."""

    scope_kind: str
    target_ref: str
    artifacts: Mapping[str, str]
    findings: Mapping[str, FindingRef]
    correlations: Mapping[str, str]
    correlation_findings: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class BuiltInvestigationInput:
    """Payload to send plus references that must remain application-side."""

    payload: dict[str, object]
    references: InvestigationReferences


def build_investigation_input(
    *,
    user_request: str,
    scope: FindingRef | Correlation,
    artifacts: Iterable[tuple[str, Sequence[Finding]]],
    correlations: Iterable[Correlation] = (),
    artifact_limitations: Mapping[str, Sequence[str]] | None = None,
    include_remediation: bool = False,
) -> BuiltInvestigationInput:
    """Build payload for exactly one current finding or one current correlation.

    ``artifacts`` must be the current successful result set. Internal IDs and
    artifact keys are used only for validation and private reference maps.
    """
    if not isinstance(user_request, str) or not user_request.strip():
        raise ValueError("user_request must be a non-empty string.")

    finding_index: dict[FindingRef, Finding] = {}
    artifact_findings: dict[str, list[Finding]] = {}
    for artifact_id, findings in artifacts:
        if not isinstance(artifact_id, str) or not artifact_id.strip():
            raise ValueError("artifact IDs must be non-empty strings.")
        current = list(findings)
        if artifact_id in artifact_findings:
            raise ValueError("Artifact IDs must be unique in the supplied current result set.")
        artifact_findings[artifact_id] = current
        for finding in current:
            if not isinstance(finding, Finding):
                raise TypeError("artifacts must contain Finding objects.")
            ref = FindingRef(artifact_id, finding.finding_id)
            previous = finding_index.get(ref)
            if previous is not None and previous != finding:
                raise ValueError("Conflicting findings share an artifact-scoped reference.")
            finding_index[ref] = finding

    current_correlations = tuple(correlations)
    selected_correlations: tuple[Correlation, ...]
    if isinstance(scope, FindingRef):
        if scope not in finding_index:
            raise ValueError("Selected finding is not present in the current artifacts.")
        selected_refs = (scope,)
        selected_correlations = ()
        scope_kind = "finding"
        selected_correlation = None
    elif isinstance(scope, Correlation):
        if scope not in current_correlations:
            raise ValueError("Selected correlation is not in the current correlation set.")
        if len(scope.finding_refs) != 2:
            raise ValueError("A selected correlation must reference exactly two findings.")
        selected_refs = scope.finding_refs
        missing = [ref for ref in selected_refs if ref not in finding_index]
        if missing:
            raise ValueError("Correlation references findings missing from current artifacts.")
        selected_correlations = (scope,)
        scope_kind = "correlation"
        selected_correlation = scope
    else:
        raise TypeError("scope must be a FindingRef or Correlation.")

    # Preserve endpoint order for correlations and deduplicate only if identical.
    ordered_refs = tuple(dict.fromkeys(selected_refs))
    internal_artifacts = tuple(dict.fromkeys(ref.artifact_id for ref in ordered_refs))
    artifact_aliases: dict[str, str] = {}
    finding_aliases: dict[FindingRef, str] = {}
    correlation_aliases: dict[str, str] = {}
    used_aliases: set[str] = set()

    for artifact_id in internal_artifacts:
        artifact_aliases[artifact_id] = _new_ref("a", used_aliases)
    for ref in ordered_refs:
        finding_aliases[ref] = _new_ref("f", used_aliases)
    for correlation in selected_correlations:
        correlation_aliases[correlation.correlation_id] = _new_ref("c", used_aliases)

    if scope_kind == "finding":
        target_ref = finding_aliases[ordered_refs[0]]
    else:
        assert selected_correlation is not None
        target_ref = correlation_aliases[selected_correlation.correlation_id]

    limitations_by_artifact = artifact_limitations or {}
    artifact_records: list[dict[str, object]] = []
    for artifact_id in internal_artifacts:
        limits = limitations_by_artifact.get(artifact_id, ())
        artifact_records.append({
            "artifact_ref": artifact_aliases[artifact_id],
            "limitations": [_redact_text(item) for item in limits],
        })

    finding_records: list[dict[str, object]] = []
    for ref in ordered_refs:
        finding = finding_index[ref]
        finding_record: dict[str, object] = {
            "finding_ref": finding_aliases[ref],
            "artifact_ref": artifact_aliases[ref.artifact_id],
            "source_type": finding.source_type.value,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": _safe_description(finding),
            "evidence": _allowlisted_evidence(finding),
        }
        if include_remediation:
            finding_record["remediation"] = {
                "text": _redact_text(finding.remediation),
                "provenance": "analyzer_advisory",
            }
        finding_records.append(finding_record)

    correlation_records: list[dict[str, object]] = []
    for correlation in selected_correlations:
        correlation_records.append({
            "correlation_ref": correlation_aliases[correlation.correlation_id],
            "relationship_type": correlation.relationship_type,
            "finding_refs": [finding_aliases[ref] for ref in correlation.finding_refs],
            "supporting_evidence": [_evidence_value(value) for value in correlation.supporting_evidence],
            "explanation": correlation.explanation,
            "limitations": list(correlation.limitations),
        })

    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "user_request": user_request.strip(),
        "scope": {"kind": scope_kind, "target_ref": target_ref},
        "artifacts": artifact_records,
        "findings": finding_records,
        "correlations": correlation_records,
    }
    refs = InvestigationReferences(
        scope_kind=scope_kind,
        target_ref=target_ref,
        artifacts=MappingProxyType({alias: internal for internal, alias in artifact_aliases.items()}),
        findings=MappingProxyType({alias: internal for internal, alias in finding_aliases.items()}),
        correlations=MappingProxyType({alias: internal for internal, alias in correlation_aliases.items()}),
        correlation_findings=MappingProxyType({
            correlation_aliases[correlation.correlation_id]: tuple(
                finding_aliases[ref] for ref in correlation.finding_refs
            )
            for correlation in selected_correlations
        }),
    )
    return BuiltInvestigationInput(payload, refs)


def resolve_citation(
    references: InvestigationReferences,
    opaque_ref: str,
) -> tuple[str, str | FindingRef] | None:
    """Resolve one response citation; unknown or wrong-request refs return None."""
    if opaque_ref in references.findings:
        return "finding", references.findings[opaque_ref]
    if opaque_ref in references.correlations:
        return "correlation", references.correlations[opaque_ref]
    if opaque_ref in references.artifacts:
        return "artifact", references.artifacts[opaque_ref]
    return None


def _new_ref(prefix: str, used: set[str]) -> str:
    while True:
        alias = f"{prefix}_{secrets.token_urlsafe(12)}"
        if alias not in used:
            used.add(alias)
            return alias


def _allowlisted_evidence(finding: Finding) -> list[dict[str, object]]:
    evidence = finding.evidence
    rule_id = evidence.get("rule_id")
    if not isinstance(rule_id, str):
        raise ValueError("Finding is missing a string evidence.rule_id.")
    values: list[tuple[str, object, str]] = [("rule_id", rule_id, "analyzer_evidence")]

    if finding.source_type is SourceType.IAM:
        if rule_id not in {
            "unrestricted-wildcard-allow", "service-wide-iam-actions", "sensitive-iam-actions",
        }:
            raise ValueError(f"Unsupported IAM rule: {rule_id}.")
        required = {"statement_index", "Effect", "Action", "Resource"}
        if not required.issubset(evidence):
            raise ValueError("IAM finding is missing required statement evidence.")
        if rule_id == "sensitive-iam-actions" and not isinstance(evidence.get("matched_actions"), list):
            raise ValueError("IAM sensitive-action finding is missing matched_actions.")
        for key in ("statement_index", "Effect", "Action", "Resource", "Sid", "matched_actions"):
            if key not in evidence:
                continue
            raw = evidence[key]
            if key == "Resource":
                raw = _redact_value(raw)
            elif key == "Sid":
                raw = "[REDACTED]"
            values.append((key, raw, "analyzer_evidence"))
        # IAM Condition is intentionally never selected.
    elif finding.source_type is SourceType.CLOUDTRAIL:
        rule_fields = {
            "trail-stop-logging": ("cloudtrail.amazonaws.com", "StopLogging", "error_absent"),
            "trail-delete": ("cloudtrail.amazonaws.com", "DeleteTrail", "error_absent"),
            "iam-create-access-key": ("iam.amazonaws.com", "CreateAccessKey", "error_absent"),
            "console-login-without-mfa": ("signin.amazonaws.com", "ConsoleLogin", "console"),
        }
        if rule_id not in rule_fields:
            raise ValueError(f"Unsupported CloudTrail rule: {rule_id}.")
        event = evidence.get("event")
        if not isinstance(event, Mapping):
            raise ValueError("CloudTrail finding is missing its event mapping.")
        source, name, mode = rule_fields[rule_id]
        if event.get("eventSource") != source or event.get("eventName") != name:
            raise ValueError("CloudTrail event does not match the finding's rule.")
        values.extend((
            ("event.eventSource", source, "analyzer_evidence"),
            ("event.eventName", name, "analyzer_evidence"),
        ))
        if mode == "error_absent":
            if "errorCode" in event:
                raise ValueError("CloudTrail API finding unexpectedly contains errorCode.")
            values.append(("errorCode_status", "absent", "application_derived"))
        else:
            additional = event.get("additionalEventData")
            response = event.get("responseElements")
            if not isinstance(additional, Mapping) or additional.get("MFAUsed") != "No":
                raise ValueError("CloudTrail console finding lacks the matched MFA evidence.")
            if not isinstance(response, Mapping) or response.get("ConsoleLogin") != "Success":
                raise ValueError("CloudTrail console finding lacks the matched response evidence.")
            values.extend((
                ("event.additionalEventData.MFAUsed", "No", "analyzer_evidence"),
                ("event.responseElements.ConsoleLogin", "Success", "analyzer_evidence"),
            ))
    elif finding.source_type is SourceType.TERRAFORM:
        supported = {
            "s3-public-acl": ("acl",),
            "s3-public-access-control-disabled": (
                "block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets",
            ),
            "security-group-public-admin-ingress": (
                "protocol", "public_cidrs", "from_port", "to_port",
            ),
        }
        if rule_id not in supported:
            raise ValueError(f"Unsupported Terraform rule: {rule_id}.")
        configured = evidence.get("configured_values")
        if not isinstance(configured, Mapping):
            raise ValueError("Terraform finding is missing configured_values.")
        if rule_id == "s3-public-acl":
            if configured.get("acl") not in {"public-read", "public-read-write"}:
                raise ValueError("Terraform ACL finding lacks a supported public ACL value.")
            configured_values = {"acl": configured["acl"]}
        elif rule_id == "s3-public-access-control-disabled":
            configured_values = {
                key: False for key in supported[rule_id]
                if configured.get(key) is False
            }
            if not configured_values:
                raise ValueError("Terraform public-access finding lacks an explicit false setting.")
        else:
            configured_values = {
                key: configured[key] for key in supported[rule_id]
                if key in configured
            }
            protocol = configured_values.get("protocol")
            cidrs = configured_values.get("public_cidrs")
            is_tcp = isinstance(protocol, str) and (protocol.casefold() == "tcp" or protocol == "6")
            if (protocol != "-1" and not is_tcp) or not isinstance(cidrs, list) or not cidrs:
                raise ValueError("Terraform ingress finding lacks supported protocol or CIDR evidence.")
            if any(cidr not in {"0.0.0.0/0", "::/0"} for cidr in cidrs):
                raise ValueError("Terraform ingress finding contains an unsupported public CIDR value.")
            if is_tcp:
                start, end = configured_values.get("from_port"), configured_values.get("to_port")
                if (
                    not isinstance(start, int) or isinstance(start, bool)
                    or not isinstance(end, int) or isinstance(end, bool)
                    or not any(start <= port <= end for port in (22, 3389))
                ):
                    raise ValueError("Terraform ingress finding lacks matching TCP port evidence.")
        for key, value in configured_values.items():
            values.append((f"configured_values.{key}", value, "analyzer_evidence"))
        address = evidence.get("resource_address")
        if isinstance(address, str) and address:
            values.append(("resource_address", _redact_terraform_address(address), "application_derived"))
    else:
        raise ValueError(f"Unsupported finding source: {finding.source_type.value}.")

    return [
        {"path": path, "value": value, "provenance": provenance}
        for path, value, provenance in values
    ]


def _evidence_value(value: EvidenceValue) -> dict[str, str]:
    return {"path": value.path, "value": value.value, "provenance": "analyzer_evidence"}


def _safe_description(finding: Finding) -> str:
    description = finding.description
    address = finding.evidence.get("resource_address")
    if finding.source_type is SourceType.TERRAFORM and isinstance(address, str):
        description = description.replace(address, _redact_terraform_address(address))
    return _redact_text(description)


def _redact_value(value: object) -> object:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item) for item in value]
    return value


_ARN_RE = re.compile(r"arn:([^:]+):([^:]+):([^:]*):([^:]*):([^\s,\]]+)")
_ACCOUNT_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_TF_ADDRESS_RE = re.compile(r"\b(aws_[A-Za-z0-9_]+)\.([A-Za-z0-9_-]+)(\.ingress\[\d+\])?")


def _redact_text(value: str) -> str:
    def redact_arn(match: re.Match[str]) -> str:
        partition, service, region, _account, resource = match.groups()
        if resource == "*":
            safe_resource = "*"
        elif "/" in resource:
            safe_resource = resource.split("/", 1)[0] + "/[REDACTED_RESOURCE]"
        else:
            safe_resource = "[REDACTED_RESOURCE]"
        return f"arn:{partition}:{service}:{region}:[REDACTED_ACCOUNT]:{safe_resource}"

    redacted = _TF_ADDRESS_RE.sub(
        lambda match: f"{match.group(1)}.<resource>{match.group(3) or ''}", value,
    )
    redacted = _ARN_RE.sub(redact_arn, redacted)
    return _ACCOUNT_RE.sub("[REDACTED_ACCOUNT]", redacted)


def _redact_terraform_address(value: str) -> str:
    return _TF_ADDRESS_RE.sub(lambda match: f"{match.group(1)}.<resource>{match.group(3) or ''}", value)
