"""Streamlit upload interface for CloudOps Agent."""

import streamlit as st

from cloudops_agent.analysis_state import (
    analysis_result_key,
    clear_inactive_analysis_results,
    current_finding_artifacts,
)
from cloudops_agent.cloudtrail_analyzer import (
    CloudTrailValidationError,
    analyze_cloudtrail_events,
)
from cloudops_agent.correlation import Correlation, FindingRef, correlate_findings
from cloudops_agent.investigation_display import (
    VALIDATION_DISCLAIMER,
    render_investigation_output,
)
from cloudops_agent.investigation_output import InvestigationOutput
from cloudops_agent.investigation_workflow import (
    active_investigation_result_keys,
    build_correlation_investigation,
    build_finding_investigation,
    clear_inactive_investigation_results,
    correlation_investigation_key,
    execute_investigation_action,
    finding_investigation_key,
)
from cloudops_agent.iam_analyzer import IAMPolicyValidationError, analyze_iam_policy
from cloudops_agent.terraform_analyzer import TerraformValidationError, analyze_terraform
from cloudops_agent.uploads import UploadValidationError, process_upload


st.set_page_config(page_title="CloudOps Agent", page_icon="☁️", layout="wide")

st.title("☁️ CloudOps Agent")
st.caption("Prepare cloud investigation inputs in one place.")
st.info(
    "IAM policies can be checked locally against a small set of deterministic rules. "
    "CloudTrail logs can be checked locally against a small set of deterministic rules. "
    "Terraform files can be checked locally against a small set of deterministic rules. "
    "No AWS connection is made and uploaded content is never executed."
)

columns = st.columns(3)
uploaders = [
    (columns[0], "CloudTrail logs", "Upload CloudTrail-style JSON logs", ["json"]),
    (columns[1], "AWS IAM policy", "Upload AWS IAM policy JSON", ["json"]),
    (columns[2], "Terraform configuration", "Upload AWS Terraform .tf files", ["tf"]),
]

active_cloudtrail_result_keys: set[str] = set()
active_iam_result_keys: set[str] = set()
active_terraform_result_keys: set[str] = set()
pending_investigation: tuple[str, object, str] | None = None

for column, input_type, label, extensions in uploaders:
    with column:
        st.subheader(input_type)
        files = st.file_uploader(
            label,
            type=extensions,
            accept_multiple_files=True,
            key=input_type,
            help="Maximum size: 5 MB per file. Uploaded content is never executed.",
        )
        if input_type == "AWS IAM policy" and not files:
            st.caption("Upload an IAM policy JSON file to enable analysis.")
        if input_type == "Terraform configuration" and not files:
            st.caption("Upload a Terraform .tf file to enable analysis.")

        for file_index, uploaded_file in enumerate(files):
            content = uploaded_file.getvalue()
            if input_type == "CloudTrail logs":
                cloudtrail_result_key = analysis_result_key("cloudtrail", file_index, content)
                active_cloudtrail_result_keys.add(cloudtrail_result_key)
            elif input_type == "AWS IAM policy":
                iam_result_key = analysis_result_key("iam", file_index, content)
                active_iam_result_keys.add(iam_result_key)
            elif input_type == "Terraform configuration":
                terraform_result_key = analysis_result_key("terraform", file_index, content)
                active_terraform_result_keys.add(terraform_result_key)
            try:
                result = process_upload(uploaded_file.name, content, input_type)
            except UploadValidationError as error:
                st.error(f"{uploaded_file.name}: {error}")
                continue
            st.text(f"File: {result.filename} · Type: {result.input_type} · Size: {result.size_bytes:,} bytes")
            st.caption(result.summary)

            if input_type == "CloudTrail logs":
                result_key = cloudtrail_result_key
                button_key = result_key.replace("-result-", "-button-", 1)
                if st.button("Analyze CloudTrail logs", key=button_key):
                    try:
                        findings = analyze_cloudtrail_events(result.parsed_document)
                    except CloudTrailValidationError as error:
                        st.session_state[result_key] = {"error": str(error)}
                    else:
                        st.session_state[result_key] = {"findings": findings}

                analysis_result = st.session_state.get(result_key)
                if analysis_result is not None:
                    if "error" in analysis_result:
                        st.error(f"CloudTrail logs could not be analyzed: {analysis_result['error']}")
                    else:
                        findings = analysis_result["findings"]
                        if not findings:
                            st.info(
                                "No configured CloudTrail analysis rules matched these logs. "
                                "This does not mean the events or account are safe."
                            )
                        for finding in findings:
                            with st.expander(f"{finding.title} · {finding.severity.value}"):
                                finding_ref = FindingRef(result_key, finding.finding_id)
                                if st.button(
                                    "Investigate with AI",
                                    key=f"{finding_investigation_key(finding_ref)}-button",
                                ):
                                    pending_investigation = (
                                        "finding",
                                        finding_ref,
                                        f"{finding.source_type.value}: {finding.title}",
                                    )
                                st.markdown(f"**Severity:** {finding.severity.value}")
                                event_evidence = finding.evidence.get("event", {})
                                event_id = finding.evidence.get("eventID")
                                if event_id is not None:
                                    st.markdown(f"**Event ID:** {event_id}")
                                if isinstance(event_evidence, dict):
                                    st.markdown(
                                        "**Event:** "
                                        f"{event_evidence.get('eventSource', 'Unknown source')} · "
                                        f"{event_evidence.get('eventName', 'Unknown event')}"
                                    )
                                st.markdown("**Description**")
                                st.write(finding.description)
                                st.markdown("**Evidence**")
                                st.json(dict(finding.evidence))
                                st.markdown("**Remediation**")
                                st.write(finding.remediation)
                continue

            if input_type == "Terraform configuration":
                result_key = terraform_result_key
                button_key = result_key.replace("-result-", "-button-", 1)
                if st.button("Analyze Terraform configuration", key=button_key):
                    try:
                        analysis = analyze_terraform(result.source_text, result.filename)
                    except TerraformValidationError as error:
                        st.session_state[result_key] = {"error": str(error)}
                    else:
                        st.session_state[result_key] = {
                            "findings": analysis.findings,
                            "limitations": analysis.limitations,
                        }

                analysis_result = st.session_state.get(result_key)
                if analysis_result is not None:
                    if "error" in analysis_result:
                        st.error(f"Terraform configuration could not be analyzed: {analysis_result['error']}")
                    else:
                        findings = analysis_result["findings"]
                        limitations = analysis_result["limitations"]
                        if limitations:
                            st.warning("Analysis limitations: " + " ".join(limitations))
                        if not findings:
                            st.info(
                                "No configured Terraform analysis rules matched this file. "
                                "Only implemented checks of supported literal values were run; "
                                "dynamic values, provider defaults, modules, and deployed AWS state "
                                "were not evaluated. This does not mean the configuration is safe."
                            )
                        for finding in findings:
                            with st.expander(f"{finding.title} · {finding.severity.value}"):
                                finding_ref = FindingRef(result_key, finding.finding_id)
                                if st.button(
                                    "Investigate with AI",
                                    key=f"{finding_investigation_key(finding_ref)}-button",
                                ):
                                    pending_investigation = (
                                        "finding",
                                        finding_ref,
                                        f"{finding.source_type.value}: {finding.title}",
                                    )
                                st.markdown(f"**Severity:** {finding.severity.value}")
                                address = finding.evidence.get("resource_address")
                                if address:
                                    st.markdown(f"**Resource:** `{address}`")
                                st.markdown("**Description**")
                                st.write(finding.description)
                                st.markdown("**Evidence**")
                                st.json(dict(finding.evidence))
                                st.markdown("**Remediation**")
                                st.write(finding.remediation)
                continue

            if input_type != "AWS IAM policy":
                continue

            result_key = iam_result_key
            button_key = result_key.replace("-result-", "-button-", 1)
            if st.button("Analyze IAM policy", key=button_key):
                try:
                    findings = analyze_iam_policy(result.parsed_document)
                except IAMPolicyValidationError as error:
                    st.session_state[result_key] = {"error": str(error)}
                else:
                    st.session_state[result_key] = {"findings": findings}

            analysis_result = st.session_state.get(result_key)
            if analysis_result is None:
                continue
            if "error" in analysis_result:
                st.error(f"IAM policy could not be analyzed: {analysis_result['error']}")
                continue

            findings = analysis_result["findings"]
            if not findings:
                st.info(
                    "No configured IAM analysis rules matched this policy. "
                    "This does not mean the policy is safe."
                )
                continue

            for finding in findings:
                with st.expander(f"{finding.title} · {finding.severity.value}"):
                    finding_ref = FindingRef(result_key, finding.finding_id)
                    if st.button(
                        "Investigate with AI",
                        key=f"{finding_investigation_key(finding_ref)}-button",
                    ):
                        pending_investigation = (
                            "finding",
                            finding_ref,
                            f"{finding.source_type.value}: {finding.title}",
                        )
                    st.markdown(f"**Severity:** {finding.severity.value}")
                    statement_index = finding.evidence.get("statement_index")
                    if statement_index is not None:
                        st.markdown(f"**Statement:** {statement_index}")
                    matched_actions = finding.evidence.get("matched_actions")
                    if matched_actions:
                        st.markdown(f"**Matched actions:** {', '.join(matched_actions)}")
                    st.markdown("**Description**")
                    st.write(finding.description)
                    st.markdown("**Evidence**")
                    st.json(dict(finding.evidence))
                    st.markdown("**Remediation**")
                    st.write(finding.remediation)

clear_inactive_analysis_results(
    st.session_state,
    "iam",
    active_iam_result_keys,
)
clear_inactive_analysis_results(
    st.session_state,
    "cloudtrail",
    active_cloudtrail_result_keys,
)
clear_inactive_analysis_results(
    st.session_state,
    "terraform",
    active_terraform_result_keys,
)

correlation_artifacts = current_finding_artifacts(
    st.session_state,
    {
        "iam": active_iam_result_keys,
        "cloudtrail": active_cloudtrail_result_keys,
    },
)
correlations = correlate_findings(correlation_artifacts)
if correlations:
    st.subheader("Cross-source correlations")
    for correlation in correlations:
        with st.expander(f"{correlation.relationship_type} · {correlation.correlation_id}"):
            st.write(correlation.explanation)
            st.markdown("**Supporting evidence**")
            st.json([
                {"path": item.path, "value": item.value}
                for item in correlation.supporting_evidence
            ])
            st.markdown("**Limitations**")
            for limitation in correlation.limitations:
                st.write(limitation)
            if st.button(
                "Investigate correlation with AI",
                key=f"{correlation_investigation_key(correlation)}-button",
            ):
                pending_investigation = (
                    "correlation",
                    correlation,
                    f"Correlation: {correlation.relationship_type}",
                )

ai_artifacts = current_finding_artifacts(
    st.session_state,
    {
        "iam": active_iam_result_keys,
        "cloudtrail": active_cloudtrail_result_keys,
        "terraform": active_terraform_result_keys,
    },
)
active_ai_result_keys = active_investigation_result_keys(ai_artifacts, correlations)
clear_inactive_investigation_results(st.session_state, active_ai_result_keys)

if pending_investigation is not None:
    action_kind, selected_scope, scope_label = pending_investigation
    if action_kind == "finding":
        assert isinstance(selected_scope, FindingRef)
        ai_result_key = finding_investigation_key(selected_scope)
        limitations_by_artifact = {}
        for artifact_id, _findings in ai_artifacts:
            if not artifact_id.startswith("terraform-analysis-result-"):
                continue
            analysis_result = st.session_state.get(artifact_id)
            limitations = analysis_result.get("limitations") if isinstance(analysis_result, dict) else None
            if isinstance(limitations, (list, tuple)) and all(isinstance(item, str) for item in limitations):
                limitations_by_artifact[artifact_id] = tuple(limitations)
        try:
            built_input = build_finding_investigation(
                selected_scope,
                artifacts=ai_artifacts,
                correlations=correlations,
                artifact_limitations=limitations_by_artifact,
            )
        except (TypeError, ValueError):
            st.session_state[ai_result_key] = {
                "status": "error",
                "label": scope_label,
                "message": "The selected finding is no longer current. Run deterministic analysis again.",
            }
        else:
            with st.spinner("Investigating selected evidence…"):
                execute_investigation_action(
                    st.session_state,
                    ai_result_key,
                    built_input,
                    requested=True,
                    label=scope_label,
                )
    else:
        assert isinstance(selected_scope, Correlation)
        ai_result_key = correlation_investigation_key(selected_scope)
        try:
            built_input = build_correlation_investigation(
                selected_scope,
                artifacts=ai_artifacts,
                correlations=correlations,
            )
        except (TypeError, ValueError):
            st.session_state[ai_result_key] = {
                "status": "error",
                "label": scope_label,
                "message": "The selected correlation is no longer current. Refresh the analysis and try again.",
            }
        else:
            with st.spinner("Investigating correlated evidence…"):
                execute_investigation_action(
                    st.session_state,
                    ai_result_key,
                    built_input,
                    requested=True,
                    label=scope_label,
                )

visible_ai_results = [
    (key, st.session_state.get(key))
    for key in sorted(active_ai_result_keys)
    if st.session_state.get(key) is not None
]
if visible_ai_results:
    st.subheader("AI-generated investigation output")
    st.caption(VALIDATION_DISCLAIMER)
    for result_key, record in visible_ai_results:
        if not isinstance(record, dict):
            continue
        label = record.get("label")
        if not isinstance(label, str):
            label = "Investigation"
        with st.expander(label):
            if record.get("status") == "error":
                message = record.get("message")
                st.error(message if isinstance(message, str) else "AI investigation could not be completed.")
            elif record.get("status") == "success" and isinstance(record.get("output"), InvestigationOutput):
                render_investigation_output(st, record["output"])
