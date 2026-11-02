# Investigation Input Contract and Provider Boundary

This document describes the provider-independent investigation input boundary.
Deterministic analyzers remain responsible for parsing and detection; the AI
receives only the selected structured findings and correlations. The current
provider adapter design is documented in [Meta provider integration](meta-provider-integration.md).

## Scope and references

One request covers exactly one selected finding or one selected correlation. A
correlation request includes both current findings it references. The application
must resolve every correlation endpoint against the current successful result set
before building a request. If either endpoint is missing, stale, conflicting, or
outside the selected context, omit the correlation and fail request construction.

The request uses fresh opaque `artifact_ref`, `finding_ref`, and `correlation_ref`
aliases. Internal finding IDs, correlation IDs, session-state keys, content hashes,
filenames, and original uploaded content stay in application-side maps. Opaque
aliases are valid for one request only. Validate citations against that request's
maps before displaying an AI response, then map valid citations back to local
records.

## Evidence allowlists

- **IAM:** allow `rule_id`, `statement_index`, `Effect`, `Action`, `Resource`,
  optional `Sid`, and `matched_actions` when present. Never include `Condition`.
  Selectively redact account IDs and ARN resource identifiers while preserving
  useful action/resource structure.
- **CloudTrail:** never include the full event. For the first three current rules,
  allow `eventSource`, `eventName`, and application-derived
  `errorCode_status: "absent"`. For console login without MFA, allow
  `eventSource`, `eventName`, `additionalEventData.MFAUsed`, and
  `responseElements.ConsoleLogin`. Omit event IDs and identity/network/request/
  and unrelated response details by default.
- **Terraform:** allow `rule_id` and only the matching rule's configured values.
  `resource_address` may be included as a locator with resource labels redacted.
  Exclude filenames, raw HCL, full resources, and unrelated attributes.

Sensitive identifiers are selectively redacted before external transmission. The
application must not serialize full dataclasses or evidence mappings.

## Limitations and provenance

Terraform limitations are returned as a tuple on the artifact-level
`TerraformAnalysisResult`; the implementation does not reliably associate each
limitation with a particular finding. Include applicable limitations with the
artifact. IAM and CloudTrail have no separate structured limitations field; their
caveats are in analyzer-authored finding descriptions. Correlation limitations
belong to each correlation.

Evidence fields identify their origin as `analyzer_evidence` or
`application_derived`. Opaque references, explicit absent-key indicators, and
selected scope are application-derived. Selected values copied from analyzer
evidence are analyzer evidence. Existing analyzer descriptions and remediation
text are analyzer-authored; remediation is advisory and is omitted unless the
user asks for recommendations.

## Conceptual request schema

The names below are the proposed wire contract; they are not currently used by an
AI integration.

```text
InvestigationInput
  schema_version: "1"
  user_request: str
  scope:
    kind: "finding" | "correlation"
    target_ref: finding_ref | correlation_ref
  artifacts: list[
    {artifact_ref: str, limitations: list[str]}
  ]
  findings: list[
    {
      finding_ref: str,
      artifact_ref: str,
      source_type: "IAM" | "CloudTrail" | "Terraform",
      severity: "Critical" | "High" | "Medium" | "Low" | "Informational",
      title: str,
      description: str,
      evidence: list[{path: str, value: JSONValue, provenance: str}],
      remediation?: {text: str, provenance: "analyzer_advisory"}
    }
  ]
  correlations: list[
    {
      correlation_ref: str,
      relationship_type: str,
      finding_refs: list[finding_ref],
      supporting_evidence: list[{path: str, value: str, provenance: str}],
      explanation: str,
      limitations: list[str]
    }
  ]
```

Each factual AI claim must cite one or more supplied opaque finding or correlation
references. Correlation remains evidence overlap only; it does not prove shared
identity, authorization, or causation. AI recommendations are advisory. Do not
execute them, call AWS, enrich with external information, or pass unrelated app or
session state.

## Output contract and validation boundary

`src/cloudops_agent/investigation_output.py` implements the provider-independent
parser and validator for the following JSON response contract. It does not call a
provider and is not connected to the Streamlit UI.

The provider-independent output contract uses schema version `1`:

```text
InvestigationOutput
  schema_version: "1"
  summary: {text: str, references: list[opaque_ref]}
  observations: list[
    {
      claim: str,
      basis: "direct_evidence" | "interpretation",
      references: list[opaque_ref],
      uncertainty: {present: bool, note: str | null}
    }
  ]
  limitations: list[{text: str, references: list[opaque_ref]}]
  recommendations: list[
    {
      type: "investigation" | "remediation",
      priority: "high" | "medium" | "low",
      action: str,
      rationale: str,
      references: list[opaque_ref],
      uncertainty: {present: bool, note: str | null}
    }
  ]
```

Every observation and recommendation must cite at least one supplied finding or
correlation. Summary and limitation entries also require citations. Uncertainty
must have a meaningful note when `present` is true and a null note when false. No
numerical confidence score is part of the contract.

The validator checks JSON structure, exact properties and types, field lengths,
list sizes, enums, uncertainty consistency, and citations against the maps for
that request. A valid citation proves only that a supplied reference exists. It
does not prove that the cited evidence supports a claim; structural validation
cannot guarantee semantic correctness. The model must not present unverified
interpretations as established facts. Recommendations are advisory and are never
executed automatically.

Uploaded IAM, CloudTrail, and Terraform values are untrusted data, not instructions.
They cannot override investigation rules or request more scope, secrets, or
unsupported conclusions. Do not execute, evaluate, or interpret uploaded strings
as code. JSON validation and string matching do not solve prompt injection;
provider-specific role separation and request construction remain future work.

On validation failure, return no displayable model content and show a clear
user-facing error. The current provider adapter performs no retries. Never expose
credentials in prompts, logs, errors, or rendered output; avoid unnecessary
full-prompt/response logging. Never execute commands, apply patches, call AWS, or
modify infrastructure automatically.
