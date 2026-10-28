"""Static checks for a small, explicit subset of AWS Terraform configuration."""

from collections.abc import Mapping
from dataclasses import dataclass
import re

import hcl2
from hcl2 import SerializationOptions

from cloudops_agent.models import Finding, Severity, SourceType


class TerraformValidationError(ValueError):
    """Raised when an uploaded file is not valid HCL2 or has an invalid structure."""


@dataclass(frozen=True)
class TerraformAnalysisResult:
    """Findings plus places where static configuration prevented a check."""

    findings: list[Finding]
    limitations: tuple[str, ...]


_PUBLIC_S3_ACLS = {"public-read", "public-read-write"}
_S3_PUBLIC_ACCESS_SETTINGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)
_ADMIN_PORTS = {22, 3389}


def analyze_terraform(source_text: str, filename: str = "uploaded.tf") -> TerraformAnalysisResult:
    """Inspect literal settings in one Terraform HCL2 file without executing it.

    Variable values, modules, provider defaults, and deployed resource state are
    not resolved. Only the explicitly supported resource attributes are checked.
    """
    if not isinstance(source_text, str):
        raise TerraformValidationError("Terraform input must be text.")
    if not isinstance(filename, str) or not filename.strip():
        raise TerraformValidationError("Terraform filename must be a non-empty string.")

    try:
        document = hcl2.loads(
            source_text,
            serialization_options=SerializationOptions(
                explicit_blocks=False,
                strip_string_quotes=True,
                with_comments=False,
            ),
        )
    except Exception as exc:
        # Parser exceptions vary by HCL syntax error; present one safe input error
        # instead of exposing a traceback in the Streamlit interface.
        raise TerraformValidationError(f"{filename}: invalid HCL2 syntax.") from exc

    resources = _extract_resources(document, filename)
    findings: list[Finding] = []
    limitations: set[str] = set()

    if document.get("module"):
        limitations.add("Module contents are not expanded or analyzed.")

    for resource_type, resource_name, body in resources:
        address = f"{resource_type}.{resource_name}"
        if "for_each" in body or "count" in body:
            limitations.add(f"Resource instances are not expanded for {address}.")

        if resource_type == "aws_s3_bucket_acl":
            _check_s3_acl(filename, address, body, findings, limitations)
        elif resource_type == "aws_s3_bucket_public_access_block":
            _check_s3_public_access(filename, address, body, findings, limitations)
        elif resource_type == "aws_security_group":
            _check_security_group(filename, address, body, findings, limitations)
        elif resource_type == "aws_vpc_security_group_ingress_rule":
            limitations.add(
                f"Standalone ingress rule {address} is not analyzed; only inline aws_security_group ingress is supported."
            )

    return TerraformAnalysisResult(findings, tuple(sorted(limitations)))


def _extract_resources(
    document: object, filename: str
) -> list[tuple[str, str, Mapping[str, object]]]:
    if not isinstance(document, Mapping):
        raise TerraformValidationError(f"{filename}: HCL document must have a block structure.")
    raw_resources = document.get("resource", [])
    if not isinstance(raw_resources, list):
        raise TerraformValidationError(f"{filename}: resource blocks have an unsupported structure.")

    resources: list[tuple[str, str, Mapping[str, object]]] = []
    for group_index, group in enumerate(raw_resources, start=1):
        if not isinstance(group, Mapping):
            raise TerraformValidationError(
                f"{filename}: resource block group {group_index} has an unsupported structure."
            )
        for resource_type, named_resources in group.items():
            if not isinstance(resource_type, str) or not isinstance(named_resources, Mapping):
                raise TerraformValidationError(
                    f"{filename}: resource block labels or names have an unsupported structure."
                )
            for resource_name, body in named_resources.items():
                if not isinstance(resource_name, str) or not isinstance(body, Mapping):
                    raise TerraformValidationError(
                        f"{filename}: resource '{resource_type}' has an unsupported body."
                    )
                resources.append((resource_type, resource_name, body))
    return resources


def _check_s3_acl(
    filename: str,
    address: str,
    body: Mapping[str, object],
    findings: list[Finding],
    limitations: set[str],
) -> None:
    if "acl" not in body:
        return
    acl = body["acl"]
    if _is_expression(acl) or not isinstance(acl, str):
        limitations.add(f"S3 ACL value for {address} is not a supported literal; this check was skipped.")
        return
    if acl not in _PUBLIC_S3_ACLS:
        return
    findings.append(
        _finding(
            rule_id="s3-public-acl",
            address=address,
            filename=filename,
            severity=Severity.HIGH,
            title="S3 bucket ACL is configured for public access",
            description=(
                f"The {address} resource explicitly configures ACL '{acl}'. "
                "This indicates public ACL intent in the configuration; it does not "
                "establish effective or deployed public access."
            ),
            configured_values={"acl": acl},
            remediation=(
                "Use a private ACL or another access-control design required by the "
                "application, and verify the bucket's public-access controls separately."
            ),
        )
    )


def _check_s3_public_access(
    filename: str,
    address: str,
    body: Mapping[str, object],
    findings: list[Finding],
    limitations: set[str],
) -> None:
    explicitly_disabled: dict[str, bool] = {}
    for setting in _S3_PUBLIC_ACCESS_SETTINGS:
        if setting not in body:
            continue
        value = body[setting]
        if isinstance(value, bool):
            if value is False:
                explicitly_disabled[setting] = False
        else:
            limitations.add(
                f"S3 public-access setting '{setting}' for {address} is not a supported literal; this check was skipped for that setting."
            )
    if not explicitly_disabled:
        return
    settings_text = ", ".join(sorted(explicitly_disabled))
    findings.append(
        _finding(
            rule_id="s3-public-access-control-disabled",
            address=address,
            filename=filename,
            severity=Severity.MEDIUM,
            title="S3 public-access block setting is explicitly disabled",
            description=(
                f"The {address} resource explicitly sets {settings_text} to false. "
                "This removes configured protections but does not prove the bucket "
                "is publicly accessible."
            ),
            configured_values=explicitly_disabled,
            remediation=(
                "Set the applicable public-access block settings to true unless a "
                "reviewed use case requires otherwise; this recommendation does not "
                "establish the correct setting for every workload."
            ),
        )
    )


def _check_security_group(
    filename: str,
    address: str,
    body: Mapping[str, object],
    findings: list[Finding],
    limitations: set[str],
) -> None:
    if "dynamic" in body:
        limitations.add(f"Dynamic blocks in {address} are not evaluated.")

    ingress_blocks = body.get("ingress", [])
    if isinstance(ingress_blocks, Mapping):
        ingress_items = [ingress_blocks]
    elif isinstance(ingress_blocks, list):
        ingress_items = ingress_blocks
    elif "ingress" in body:
        limitations.add(f"Ingress rules for {address} use an unsupported structure; those checks were skipped.")
        return
    else:
        return

    for index, ingress in enumerate(ingress_items, start=1):
        if not isinstance(ingress, Mapping):
            limitations.add(f"Ingress rule {index} in {address} has an unsupported structure; it was skipped.")
            continue

        public_cidrs = _public_cidrs(ingress, address, index, limitations)
        protocol = ingress.get("protocol")
        if _is_expression(protocol) or not isinstance(protocol, str):
            protocol_indeterminate = "protocol" in ingress
            if protocol_indeterminate:
                limitations.add(f"Ingress protocol for {address} rule {index} is not a supported literal.")
            else:
                protocol_indeterminate = True
                limitations.add(f"Ingress protocol for {address} rule {index} is missing.")
        else:
            protocol_indeterminate = False

        if not public_cidrs:
            continue

        port_values: dict[str, object] = {}
        if protocol == "-1" and not protocol_indeterminate:
            is_admin_access = True
        elif not protocol_indeterminate and (protocol.casefold() == "tcp" or protocol == "6"):
            from_port = ingress.get("from_port")
            to_port = ingress.get("to_port")
            if not _is_integer(from_port) or not _is_integer(to_port):
                if "from_port" in ingress or "to_port" in ingress:
                    limitations.add(f"Ingress ports for {address} rule {index} are not supported integer literals.")
                else:
                    limitations.add(f"Ingress ports for {address} rule {index} are missing.")
                continue
            port_values = {"from_port": from_port, "to_port": to_port}
            is_admin_access = any(from_port <= port <= to_port for port in _ADMIN_PORTS)
        else:
            continue

        if not is_admin_access:
            continue
        findings.append(
            _finding(
                rule_id="security-group-public-admin-ingress",
                address=f"{address}.ingress[{index}]",
                filename=filename,
                severity=Severity.HIGH,
                title="Security group allows internet-wide SSH or RDP ingress",
                description=(
                    f"The {address} ingress rule has a public CIDR ({', '.join(public_cidrs)}) "
                    + ("and allows all protocols. " if protocol == "-1" else "and includes TCP port 22 or 3389. ")
                    + "This indicates broad inbound access in the configuration; it does not "
                    "establish that a deployed resource is reachable."
                ),
                configured_values={
                    "protocol": protocol,
                    "public_cidrs": public_cidrs,
                    **port_values,
                },
                remediation=(
                    "Restrict the ingress CIDR to trusted source ranges and limit the "
                    "protocol and ports to the minimum required. Verify any network "
                    "controls separately."
                ),
            )
        )


def _public_cidrs(
    ingress: Mapping[str, object],
    address: str,
    index: int,
    limitations: set[str],
) -> list[str]:
    public: list[str] = []
    for attribute, known_public_cidr in (
        ("cidr_blocks", "0.0.0.0/0"),
        ("ipv6_cidr_blocks", "::/0"),
    ):
        if attribute not in ingress:
            continue
        values = ingress[attribute]
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            limitations.add(f"{attribute} for {address} rule {index} is not a supported literal list.")
            continue
        for value in values:
            if _is_expression(value) or not isinstance(value, str):
                limitations.add(f"{attribute} for {address} rule {index} contains an unsupported value.")
            elif value == known_public_cidr:
                public.append(value)
    if not any(name in ingress for name in ("cidr_blocks", "ipv6_cidr_blocks")):
        limitations.add(f"CIDR values for {address} rule {index} are missing.")
    return public


def _finding(
    *,
    rule_id: str,
    address: str,
    filename: str,
    severity: Severity,
    title: str,
    description: str,
    configured_values: Mapping[str, object],
    remediation: str,
) -> Finding:
    stable_part = re.sub(r"[^A-Za-z0-9_.\[\]-]+", "_", f"{filename}:{address}")
    return Finding(
        finding_id=f"terraform.{rule_id}:{stable_part}",
        title=title,
        source_type=SourceType.TERRAFORM,
        severity=severity,
        description=description,
        evidence={
            "rule_id": rule_id,
            "filename": filename,
            "resource_address": address,
            "configured_values": dict(configured_values),
        },
        remediation=remediation,
    )


def _is_expression(value: object) -> bool:
    return isinstance(value, str) and ("${" in value or "%{" in value)


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
