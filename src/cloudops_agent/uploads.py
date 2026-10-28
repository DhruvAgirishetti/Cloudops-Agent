"""Safe validation and basic summaries for user-selected input files."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

InputType = Literal["CloudTrail logs", "AWS IAM policy", "Terraform configuration"]
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_EXTENSIONS: dict[InputType, str] = {
    "CloudTrail logs": ".json",
    "AWS IAM policy": ".json",
    "Terraform configuration": ".tf",
}


class UploadValidationError(ValueError):
    """Raised when an upload is empty, too large, or invalid for its category."""


@dataclass(frozen=True)
class UploadSummary:
    filename: str
    input_type: InputType
    summary: str
    size_bytes: int
    parsed_document: dict[str, object] | None = None


def process_upload(filename: str, content: bytes, input_type: InputType) -> UploadSummary:
    """Validate one upload and return a descriptive, non-security summary."""
    safe_name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    extension = ALLOWED_EXTENSIONS[input_type]
    if not safe_name or not safe_name.lower().endswith(extension):
        raise UploadValidationError(f"Choose a {extension} file for {input_type}.")
    if not content:
        raise UploadValidationError("The selected file is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise UploadValidationError("File exceeds the 5 MB upload limit.")

    parsed_document = None
    if input_type == "Terraform configuration":
        summary = _summarize_terraform(content)
    else:
        summary, parsed_document = _summarize_json(content, input_type)
        if input_type not in ("AWS IAM policy", "CloudTrail logs"):
            parsed_document = None
    return UploadSummary(safe_name, input_type, summary, len(content), parsed_document)


def _summarize_json(content: bytes, input_type: InputType) -> tuple[str, dict[str, object]]:
    try:
        document = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UploadValidationError("This file must contain valid UTF-8 JSON.") from exc
    if not isinstance(document, dict):
        raise UploadValidationError("Expected a JSON object at the top level.")

    if input_type == "AWS IAM policy":
        statements = document.get("Statement")
        if not isinstance(statements, (list, dict)):
            raise UploadValidationError("This does not look like an IAM policy: expected a Statement field.")
        count = len(statements) if isinstance(statements, list) else 1
        summary = f"JSON policy document with {count} statement(s). No security checks have been run."
        return summary, document

    records = document.get("Records")
    if isinstance(records, list):
        summary = f"CloudTrail-style JSON with {len(records)} record(s)."
        return summary, document
    if "eventName" in document:
        summary = "Single CloudTrail-style event record."
        return summary, document
    summary = "Valid JSON object; CloudTrail record structure was not identified. No security checks have been run."
    return summary, document


def _summarize_terraform(content: bytes) -> str:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise UploadValidationError("Terraform files must use UTF-8 text encoding.") from exc
    aws_providers = len(re.findall(r"\bprovider\s+\"aws\"\s*\{", text))
    resource_blocks = len(re.findall(r"\bresource\s+\"[^\"]+\"\s+\"[^\"]+\"\s*\{", text))
    return (
        f"Terraform text with {resource_blocks} resource block(s) and "
        f"{aws_providers} AWS provider block(s) by simple text count. "
        "Configuration was not executed or security-checked."
    )
