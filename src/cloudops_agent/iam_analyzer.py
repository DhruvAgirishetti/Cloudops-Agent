"""Deterministic checks for a supported subset of AWS identity policies."""

from collections.abc import Mapping
import re

from cloudops_agent.models import Finding, Severity, SourceType


class IAMPolicyValidationError(ValueError):
    """Raised when a policy is malformed or outside the supported subset."""


_SENSITIVE_IAM_ACTIONS = (
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
)
_SUPPORTED_POLICY_VERSIONS = {"2008-10-17", "2012-10-17"}

_UNSUPPORTED_STATEMENT_FIELDS = {
    "NotAction": "NotAction",
    "NotResource": "NotResource",
    "Principal": "Principal",
    "NotPrincipal": "NotPrincipal",
}


def analyze_iam_policy(policy_document: object) -> list[Finding]:
    """Analyze a parsed identity-based IAM policy without contacting AWS.

    This checks the policy document's static contents only. It does not
    determine effective permissions, evaluate conditions, or prove that an
    action is exploitable.
    """
    statements = _validate_policy_document(policy_document)
    findings: list[Finding] = []

    for statement_index, normalized in enumerate(statements, start=1):
        statement = normalized["statement"]
        effect = normalized["effect"]
        actions = normalized["actions"]
        resources = normalized["resources"]

        if effect != "Allow":
            continue

        action_is_all = any(_is_all_wildcard(value) for value in actions)
        resource_is_all = any(_is_all_wildcard(value) for value in resources)

        if action_is_all and resource_is_all:
            findings.append(
                _make_finding(
                    rule_id="unrestricted-wildcard-allow",
                    statement_index=statement_index,
                    statement=statement,
                    severity=Severity.HIGH,
                    title="Allow statement covers all actions and resources",
                    description=(
                        "The policy document contains an Allow statement whose "
                        "Action and Resource values each use an all-character '*' wildcard. "
                        + _condition_note(statement)
                        + "This static finding does not establish effective access."
                    ),
                    remediation=(
                        "Replace the wildcard action and resource values with "
                        "the specific actions and resources the identity needs."
                    ),
                )
            )
            continue

        if resource_is_all and any(_is_service_wide_iam_action(action) for action in actions):
            findings.append(
                _make_finding(
                    rule_id="service-wide-iam-actions",
                    statement_index=statement_index,
                    statement=statement,
                    severity=Severity.HIGH,
                    title="Allow statement covers IAM actions on all resources",
                    description=(
                        "The policy document contains an Allow statement for "
                        "iam:* with Resource '*'. "
                        + _condition_note(statement)
                        + "This static finding does not establish effective access."
                    ),
                    remediation=(
                        "Replace iam:* with only the required IAM actions, and "
                        "limit resources to specific ARNs where those actions "
                        "support resource-level permissions."
                    ),
                )
            )
            continue

        matched_actions = [
            sensitive_action
            for sensitive_action in _SENSITIVE_IAM_ACTIONS
            if any(_action_pattern_matches(pattern, sensitive_action) for pattern in actions)
        ]
        if matched_actions:
            findings.append(
                _make_finding(
                    rule_id="sensitive-iam-actions",
                    statement_index=statement_index,
                    statement=statement,
                    severity=Severity.MEDIUM,
                    title="Allow statement includes sensitive IAM actions",
                    description=(
                        "The policy document contains an Allow statement for "
                        f"these sensitive IAM actions: {', '.join(matched_actions)}. "
                        + _condition_note(statement)
                        + "This does not prove privilege escalation or exploitability."
                    ),
                    remediation=(
                        "Confirm each action is needed and restrict it to the "
                        "smallest appropriate set of IAM resources."
                    ),
                    matched_actions=matched_actions,
                )
            )

    return findings


def _validate_policy_document(policy_document: object) -> list[dict[str, object]]:
    if not isinstance(policy_document, Mapping):
        raise IAMPolicyValidationError("Policy document must be a JSON object.")
    _validate_string_keys(policy_document, "policy document")

    if "Id" in policy_document:
        raise IAMPolicyValidationError(
            "Top-level 'Id' is not supported for identity-based policy documents."
        )
    allowed_fields = {"Version", "Statement"}
    unexpected_fields = set(policy_document) - allowed_fields
    if unexpected_fields:
        field_name = sorted(unexpected_fields)[0]
        raise IAMPolicyValidationError(
            f"Policy document contains unsupported top-level field '{field_name}'."
        )

    if "Version" in policy_document:
        version = policy_document["Version"]
        if not isinstance(version, str) or version not in _SUPPORTED_POLICY_VERSIONS:
            supported = ", ".join(sorted(_SUPPORTED_POLICY_VERSIONS))
            raise IAMPolicyValidationError(
                f"Policy document field 'Version' must be one of: {supported}."
            )

    if "Statement" not in policy_document:
        raise IAMPolicyValidationError("Policy document is missing required field 'Statement'.")

    raw_statements = policy_document["Statement"]
    if isinstance(raw_statements, Mapping):
        statement_items = [raw_statements]
    elif isinstance(raw_statements, list):
        statement_items = raw_statements
    else:
        raise IAMPolicyValidationError("'Statement' must be an object or a list of objects.")

    normalized_statements: list[dict[str, object]] = []
    seen_sids: set[str] = set()
    for statement_index, statement in enumerate(statement_items, start=1):
        normalized = _validate_statement(statement, statement_index)
        normalized_statement = normalized["statement"]
        if "Sid" in normalized_statement:
            sid = normalized_statement["Sid"]
            if sid in seen_sids:
                raise IAMPolicyValidationError(
                    f"Statement[{statement_index}] has duplicate Sid '{sid}'. Sid values must be unique."
                )
            seen_sids.add(sid)
        normalized_statements.append(normalized)
    return normalized_statements


def _validate_statement(statement: object, statement_index: int) -> dict[str, object]:
    location = f"Statement[{statement_index}]"
    if not isinstance(statement, Mapping):
        raise IAMPolicyValidationError(f"{location} must be an object.")
    _validate_string_keys(statement, location)

    for field_name, unsupported_name in _UNSUPPORTED_STATEMENT_FIELDS.items():
        if field_name in statement:
            raise IAMPolicyValidationError(
                f"{location} uses unsupported field '{unsupported_name}'."
            )

    allowed_fields = {"Sid", "Effect", "Action", "Resource", "Condition"}
    unexpected_fields = set(statement) - allowed_fields
    if unexpected_fields:
        field_name = sorted(unexpected_fields)[0]
        raise IAMPolicyValidationError(
            f"{location} contains unsupported field '{field_name}'."
        )

    for field_name in ("Effect", "Action", "Resource"):
        if field_name not in statement:
            raise IAMPolicyValidationError(
                f"{location} is missing required field '{field_name}'."
            )

    effect = statement["Effect"]
    if effect not in ("Allow", "Deny") or not isinstance(effect, str):
        raise IAMPolicyValidationError(
            f"{location} field 'Effect' must be exactly 'Allow' or 'Deny'."
        )

    actions = _normalize_string_values(statement["Action"], "Action", location)
    resources = _normalize_string_values(statement["Resource"], "Resource", location)

    if "Sid" in statement:
        sid = statement["Sid"]
        if not isinstance(sid, str) or re.fullmatch(r"[A-Za-z0-9]+", sid) is None:
            raise IAMPolicyValidationError(
                f"{location} field 'Sid' must contain only ASCII letters and digits."
            )
    if "Condition" in statement:
        if not isinstance(statement["Condition"], Mapping):
            raise IAMPolicyValidationError(f"{location} field 'Condition' must be an object.")
        _validate_string_keys(statement["Condition"], f"{location}.Condition")

    return {
        "statement": dict(statement),
        "effect": effect,
        "actions": actions,
        "resources": resources,
    }


def _normalize_string_values(value: object, field_name: str, location: str) -> tuple[str, ...]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        raise IAMPolicyValidationError(
            f"{location} field '{field_name}' must be a non-empty string or list of strings."
        )

    if not values:
        raise IAMPolicyValidationError(f"{location} field '{field_name}' must not be empty.")
    for value_index, item in enumerate(values, start=1):
        if not isinstance(item, str) or not item.strip():
            raise IAMPolicyValidationError(
                f"{location} field '{field_name}' item {value_index} must be a non-empty string."
            )
    return tuple(values)


def _validate_string_keys(value: object, location: str) -> None:
    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise IAMPolicyValidationError(
                    f"{location} contains a non-string object key: {key!r}."
                )
            _validate_string_keys(nested_value, f"{location}.{key}")
    elif isinstance(value, (list, tuple)):
        for item_index, nested_value in enumerate(value, start=1):
            _validate_string_keys(nested_value, f"{location}[{item_index}]")


def _action_pattern_matches(pattern: str, action: str) -> bool:
    """Match AWS Action wildcards against one known action, case-insensitively."""
    normalized_pattern = pattern.casefold()
    if normalized_pattern and all(character == "*" for character in normalized_pattern):
        # A bare all-actions wildcard is handled only by the unrestricted rule
        # when Resource is also '*'; don't turn it into the deferred scoped rule.
        return False

    regex_parts = []
    for character in normalized_pattern:
        if character == "*":
            regex_parts.append(".*")
        elif character == "?":
            regex_parts.append(".")
        else:
            regex_parts.append(re.escape(character))
    return re.fullmatch("".join(regex_parts), action.casefold()) is not None


def _is_all_wildcard(value: str) -> bool:
    return bool(value) and all(character == "*" for character in value)


def _is_service_wide_iam_action(action: str) -> bool:
    service, separator, action_pattern = action.partition(":")
    return (
        service.casefold() == "iam"
        and separator == ":"
        and _is_all_wildcard(action_pattern)
    )


def _condition_note(statement: Mapping[str, object]) -> str:
    if "Condition" in statement:
        return "A Condition is present, but its semantics were not evaluated. "
    return ""


def _make_finding(
    *,
    rule_id: str,
    statement_index: int,
    statement: Mapping[str, object],
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
    matched_actions: list[str] | None = None,
) -> Finding:
    evidence: dict[str, object] = {
        "rule_id": rule_id,
        "statement_index": statement_index,
        "Effect": statement["Effect"],
        "Action": statement["Action"],
        "Resource": statement["Resource"],
    }
    if "Sid" in statement:
        evidence["Sid"] = statement["Sid"]
    if "Condition" in statement:
        evidence["Condition"] = statement["Condition"]
    if matched_actions is not None:
        evidence["matched_actions"] = matched_actions

    return Finding(
        finding_id=f"iam.{rule_id}:statement-{statement_index}",
        title=title,
        source_type=SourceType.IAM,
        severity=severity,
        description=description,
        evidence=evidence,
        remediation=remediation,
    )
