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
    render_token_usage,
)
from cloudops_agent.investigation_output import InvestigationOutput
from cloudops_agent.meta_provider import MetaTokenUsage
from cloudops_agent.investigation_workflow import (
    active_investigation_result_keys,
    build_correlation_investigation,
    build_finding_investigation,
    clear_inactive_investigation_results,
    correlation_investigation_key,
    execute_investigation_action,
    finding_investigation_key,
    has_successful_investigation_result,
)
from cloudops_agent.iam_analyzer import IAMPolicyValidationError, analyze_iam_policy
from cloudops_agent.models import Finding
from cloudops_agent.terraform_analyzer import TerraformValidationError, analyze_terraform
from cloudops_agent.uploads import UploadValidationError, process_upload


st.set_page_config(page_title="CloudOps Agent", page_icon="☁️", layout="wide")

st.title("☁️ CloudOps Agent")
st.caption("Local, read-only investigation of AWS IAM policies, CloudTrail events, and Terraform configuration.")
st.info("No AWS connection is made, and uploaded content is never executed.")

st.header("1. Upload and analyze")

columns = st.columns(3)
uploaders = [
    (columns[0], "CloudTrail logs", "Upload CloudTrail-style JSON logs", ["json"]),
    (columns[1], "AWS IAM policy", "Upload AWS IAM policy JSON", ["json"]),
    (columns[2], "Terraform configuration", "Upload AWS Terraform .tf files", ["tf"]),
]

active_cloudtrail_result_keys: set[str] = set()
active_iam_result_keys: set[str] = set()
active_terraform_result_keys: set[str] = set()
pending_investigation: tuple[str, object, str, bool] | None = None
source_results: dict[str, list[tuple[str, str, object]]] = {
    "CloudTrail logs": [],
    "AWS IAM policy": [],
    "Terraform configuration": [],
}

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
                source_results[input_type].append((result.filename, result_key, analysis_result))
            elif input_type == "Terraform configuration":
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
                source_results[input_type].append((result.filename, result_key, analysis_result))
            else:
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
                source_results[input_type].append((result.filename, result_key, analysis_result))

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
correlation_findings_by_ref: dict[FindingRef, object] = {}
conflicting_correlation_finding_refs: set[FindingRef] = set()
for artifact_id, findings in correlation_artifacts:
    for finding in findings:
        finding_ref = FindingRef(artifact_id, finding.finding_id)
        existing_finding = correlation_findings_by_ref.get(finding_ref)
        if existing_finding is not None and existing_finding != finding:
            conflicting_correlation_finding_refs.add(finding_ref)
        else:
            correlation_findings_by_ref[finding_ref] = finding

st.header("3. Investigation overview")
finding_counts: dict[str, int] = {}
severity_counts = {"High": 0, "Medium": 0, "Low": 0}
for source_name, entries in source_results.items():
    finding_counts[source_name] = 0
    for _filename, _result_key, analysis_result in entries:
        if not isinstance(analysis_result, dict) or "error" in analysis_result:
            continue
        findings = analysis_result.get("findings")
        if not isinstance(findings, (list, tuple)) or any(
            not isinstance(finding, Finding) for finding in findings
        ):
            continue
        finding_counts[source_name] += len(findings)
        for finding in findings:
            if finding.severity.value in severity_counts:
                severity_counts[finding.severity.value] += 1
st.caption("Counts include successful analyses of current uploads only.")
overview_columns = st.columns(3)
overview_columns[0].metric("IAM findings", finding_counts["AWS IAM policy"])
overview_columns[1].metric("CloudTrail findings", finding_counts["CloudTrail logs"])
overview_columns[2].metric("Terraform findings", finding_counts["Terraform configuration"])
severity_columns = st.columns(3)
severity_columns[0].metric("High", severity_counts["High"])
severity_columns[1].metric("Medium", severity_counts["Medium"])
severity_columns[2].metric("Low", severity_counts["Low"])

st.header("4. Findings")
st.caption("AI investigation is a separate optional step and runs only when selected for a finding or correlation.")
finding_tabs = st.tabs(["IAM", "CloudTrail", "Terraform"])
tab_sources = (
    (finding_tabs[0], "AWS IAM policy"),
    (finding_tabs[1], "CloudTrail logs"),
    (finding_tabs[2], "Terraform configuration"),
)
for finding_tab, source_name in tab_sources:
    with finding_tab:
        entries = source_results[source_name]
        if not entries:
            st.info("Upload a file in this source section, then select its Analyze button.")
            continue
        for filename, result_key, analysis_result in entries:
            st.markdown(f"#### {filename}")
            if analysis_result is None:
                st.caption("Ready for analysis · select Analyze above.")
                continue
            if not isinstance(analysis_result, dict):
                st.error("The stored analysis result could not be read. Run analysis again.")
                continue
            if "error" in analysis_result:
                if source_name == "CloudTrail logs":
                    st.error(f"CloudTrail logs could not be analyzed: {analysis_result['error']}")
                elif source_name == "Terraform configuration":
                    st.error(f"Terraform configuration could not be analyzed: {analysis_result['error']}")
                else:
                    st.error(f"IAM policy could not be analyzed: {analysis_result['error']}")
                continue

            findings = analysis_result["findings"]
            st.caption(
                f"Analysis complete · {len(findings)} "
                f"finding{'s' if len(findings) != 1 else ''}."
            )
            if source_name == "Terraform configuration":
                limitations = analysis_result["limitations"]
                if limitations:
                    st.warning("Analysis limitations: " + " ".join(limitations))
            if not findings:
                if source_name == "CloudTrail logs":
                    st.info(
                        "No configured CloudTrail analysis rules matched these logs. "
                        "This does not mean the events or account are safe."
                    )
                elif source_name == "Terraform configuration":
                    st.info(
                        "No configured Terraform analysis rules matched this file. "
                        "Only implemented checks of supported literal values were run; "
                        "dynamic values, provider defaults, modules, and deployed AWS state "
                        "were not evaluated. This does not mean the configuration is safe."
                    )
                else:
                    st.info(
                        "No configured IAM analysis rules matched this policy. "
                        "This does not mean the policy is safe."
                    )
            for finding in findings:
                finding_ref = FindingRef(result_key, finding.finding_id)
                ai_result_key = finding_investigation_key(finding_ref)
                cached_result = has_successful_investigation_result(
                    st.session_state, ai_result_key,
                )
                if st.button(
                    "Re-investigate with AI" if cached_result else "Investigate with AI",
                    key=f"{ai_result_key}-button",
                ):
                    pending_investigation = (
                        "finding",
                        finding_ref,
                        f"{finding.source_type.value}: {finding.title}",
                        cached_result,
                    )
                with st.expander(f"{finding.severity.value} · {finding.title}"):
                    if source_name == "CloudTrail logs":
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
                    elif source_name == "Terraform configuration":
                        address = finding.evidence.get("resource_address")
                        if address:
                            st.markdown(f"**Resource:** `{address}`")
                    else:
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

st.header("5. Cross-source correlations")
if correlations:
    for correlation in correlations:
        with st.container(border=True):
            st.subheader(correlation.relationship_type.replace("_", " ").title())
            st.caption(f"Correlation ID: {correlation.correlation_id}")
            endpoint_columns = st.columns(2)
            for endpoint_index, (endpoint_column, finding_ref) in enumerate(
                zip(endpoint_columns, correlation.finding_refs),
                start=1,
            ):
                with endpoint_column:
                    endpoint = (
                        None
                        if finding_ref in conflicting_correlation_finding_refs
                        else correlation_findings_by_ref.get(finding_ref)
                    )
                    if endpoint is None:
                        st.markdown(f"**Endpoint {endpoint_index}**")
                        st.caption("The referenced current finding could not be resolved safely.")
                    else:
                        st.markdown(f"**{endpoint.source_type.value}**")
                        st.write(endpoint.title)
                    st.caption(f"Finding ID: {finding_ref.finding_id}")
            st.write(correlation.explanation)
            st.markdown("**Supporting evidence**")
            st.dataframe(
                [
                    {"Path": item.path, "Value": item.value}
                    for item in correlation.supporting_evidence
                ],
                column_order=("Path", "Value"),
                hide_index=True,
                use_container_width=True,
            )
            st.markdown("**Limitations**")
            st.warning(" ".join(correlation.limitations))
            ai_result_key = correlation_investigation_key(correlation)
            cached_result = has_successful_investigation_result(st.session_state, ai_result_key)
            if st.button(
                "Re-investigate correlation with AI" if cached_result else "Investigate correlation with AI",
                key=f"{ai_result_key}-button",
            ):
                pending_investigation = (
                    "correlation",
                    correlation,
                    f"Correlation: {correlation.relationship_type}",
                    cached_result,
                )
else:
    st.info(
        "No correlations were found under the currently supported exact-evidence rule. "
        "This does not establish that the uploaded inputs are unrelated or safe."
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
    action_kind, selected_scope, scope_label, force_reinvestigation = pending_investigation
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
                    force=force_reinvestigation,
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
                    force=force_reinvestigation,
                )

visible_ai_results = [
    (key, st.session_state.get(key))
    for key in sorted(active_ai_result_keys)
    if st.session_state.get(key) is not None
]
st.header("6. AI investigation")
if visible_ai_results:
    st.caption(VALIDATION_DISCLAIMER)
    for result_key, record in visible_ai_results:
        if not isinstance(record, dict):
            continue
        label = record.get("label")
        if not isinstance(label, str):
            label = "Investigation"
        with st.container(border=True):
            st.subheader(label)
            if record.get("status") == "error":
                message = record.get("message")
                st.error(message if isinstance(message, str) else "AI investigation could not be completed.")
            elif record.get("status") == "success" and isinstance(record.get("output"), InvestigationOutput):
                last_error = record.get("last_reinvestigation_error")
                if isinstance(last_error, str):
                    st.warning(f"Re-investigation did not complete. Showing the previous validated result. {last_error}")
                usage = record.get("usage")
                render_investigation_output(st, record["output"])
                render_token_usage(st, usage if isinstance(usage, MetaTokenUsage) else None)
else:
    st.info("AI investigations appear here after you select an explicit investigation action for a finding or correlation.")
