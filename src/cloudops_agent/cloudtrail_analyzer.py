"""Deterministic checks for selected AWS CloudTrail event patterns."""

from collections.abc import Mapping
import hashlib
import json
import math

from cloudops_agent.models import Finding, Severity, SourceType


class CloudTrailValidationError(ValueError):
    """Raised when CloudTrail input is not a supported event or log envelope."""


_RULES = {
    "trail-stop-logging": {
        "event_source": "cloudtrail.amazonaws.com",
        "event_names": {"StopLogging"},
        "severity": Severity.HIGH,
        "title": "CloudTrail StopLogging operation appears successful",
        "description": (
            "A CloudTrail StopLogging API event has no errorCode, so the operation "
            "appears successful in this record. The event alone does not confirm "
            "the trail's resulting state or indicate compromise."
        ),
        "remediation": (
            "Confirm whether the operation was authorized and verify the trail's "
            "current logging status through your approved operational process."
        ),
    },
    "trail-delete": {
        "event_source": "cloudtrail.amazonaws.com",
        "event_names": {"DeleteTrail"},
        "severity": Severity.HIGH,
        "title": "CloudTrail DeleteTrail operation appears successful",
        "description": (
            "A CloudTrail DeleteTrail API event has no errorCode, so the operation "
            "appears successful in this record. The event alone does not confirm "
            "the trail's resulting state or indicate compromise."
        ),
        "remediation": (
            "Confirm whether the operation was authorized and verify the expected "
            "trail configuration through your approved operational process."
        ),
    },
    "iam-create-access-key": {
        "event_source": "iam.amazonaws.com",
        "event_names": {"CreateAccessKey"},
        "severity": Severity.HIGH,
        "title": "IAM CreateAccessKey operation appears successful",
        "description": (
            "An IAM CreateAccessKey API event has no errorCode, so key creation "
            "appears successful in this record. This is an activity indicator, "
            "not proof of malicious behavior or key use."
        ),
        "remediation": (
            "Confirm whether the key creation was authorized and review the "
            "target identity's key inventory through your approved process."
        ),
    },
    "console-login-without-mfa": {
        "event_source": "signin.amazonaws.com",
        "event_names": {"ConsoleLogin"},
        "severity": Severity.MEDIUM,
        "title": "Successful console sign-in reported without MFA",
        "description": (
            "This CloudTrail event reports a successful console sign-in with "
            "MFAUsed set to 'No'. Review it against the account's authentication policy."
        ),
        "remediation": (
            "Confirm the sign-in was expected and ensure MFA is required for "
            "the relevant console identities."
        ),
    },
}


def analyze_cloudtrail_events(document: object) -> list[Finding]:
    """Analyze one CloudTrail event or a ``Records`` envelope without AWS access.

    This reports only the explicit event patterns below. It does not establish
    that an action was malicious or determine the current state of AWS resources.
    """
    records = _validate_document(document)
    findings: list[Finding] = []
    emitted: set[tuple[str, str]] = set()

    for record in records:
        for rule_id, rule in _RULES.items():
            if not _matches_rule(record, rule):
                continue
            identity = _event_identity(rule_id, record)
            if identity in emitted:
                continue
            emitted.add(identity)
            event_id = record.get("eventID")
            evidence: dict[str, object] = {
                "rule_id": rule_id,
                "event": dict(record),
            }
            if event_id is not None:
                evidence["eventID"] = event_id
            findings.append(
                Finding(
                    finding_id=f"cloudtrail.{rule_id}:{identity[1]}",
                    title=rule["title"],
                    source_type=SourceType.CLOUDTRAIL,
                    severity=rule["severity"],
                    description=rule["description"],
                    evidence=evidence,
                    remediation=rule["remediation"],
                )
            )
    return findings


def _validate_document(document: object) -> list[Mapping[str, object]]:
    if not isinstance(document, Mapping):
        raise CloudTrailValidationError("CloudTrail input must be an event object or log object.")
    _validate_json_value(document, "CloudTrail input")

    if "Records" in document:
        raw_records = document["Records"]
        if not isinstance(raw_records, list):
            raise CloudTrailValidationError("CloudTrail 'Records' must be a list of event objects.")
        records = raw_records
    else:
        records = [document]

    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            raise CloudTrailValidationError(f"CloudTrail record {index} must be an object.")
        for field_name in ("eventSource", "eventName"):
            value = record.get(field_name)
            if not isinstance(value, str) or not value.strip():
                raise CloudTrailValidationError(
                    f"CloudTrail record {index} must contain a non-empty '{field_name}' string."
                )
        if "eventID" in record and (
            not isinstance(record["eventID"], str) or not record["eventID"].strip()
        ):
            raise CloudTrailValidationError(
                f"CloudTrail record {index} field 'eventID' must be a non-empty string when present."
            )

    _validate_duplicate_event_ids(records)
    return records


def _validate_json_value(value: object, location: str) -> None:
    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise CloudTrailValidationError(
                    f"{location} contains a non-string object key: {key!r}."
                )
            _validate_json_value(nested_value, f"{location}.{key}")
    elif isinstance(value, list):
        for index, nested_value in enumerate(value, start=1):
            _validate_json_value(nested_value, f"{location}[{index}]")
    elif value is None or isinstance(value, (str, bool, int)):
        return
    elif isinstance(value, float) and math.isfinite(value):
        return
    else:
        raise CloudTrailValidationError(
            f"{location} contains a value that is not valid JSON data."
        )


def _validate_duplicate_event_ids(records: list[object]) -> None:
    seen: dict[str, str] = {}
    for index, record in enumerate(records, start=1):
        event_id = record.get("eventID")
        if event_id is None:
            continue
        serialized = _canonical_json(record)
        previous = seen.get(event_id)
        if previous is not None and previous != serialized:
            raise CloudTrailValidationError(
                f"CloudTrail records with eventID '{event_id}' have conflicting contents."
            )
        seen[event_id] = serialized


def _matches_rule(record: Mapping[str, object], rule: Mapping[str, object]) -> bool:
    if record.get("eventSource") != rule["event_source"]:
        return False
    if record.get("eventName") not in rule["event_names"]:
        return False

    if rule["event_source"] == "signin.amazonaws.com":
        additional = record.get("additionalEventData")
        response = record.get("responseElements")
        return (
            isinstance(additional, Mapping)
            and additional.get("MFAUsed") == "No"
            and isinstance(response, Mapping)
            and response.get("ConsoleLogin") == "Success"
        )
    return "errorCode" not in record


def _event_identity(rule_id: str, record: Mapping[str, object]) -> tuple[str, str]:
    event_id = record.get("eventID")
    if event_id is not None:
        return rule_id, event_id
    return rule_id, f"sha256-{hashlib.sha256(_canonical_json(record).encode('utf-8')).hexdigest()}"


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
