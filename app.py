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
from cloudops_agent.correlation import correlate_findings
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
