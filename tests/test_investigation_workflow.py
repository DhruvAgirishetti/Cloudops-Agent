import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.correlation import Correlation, EvidenceValue, FindingRef
from cloudops_agent.investigation_display import render_investigation_output, render_token_usage
from cloudops_agent.investigation_output import InvestigationOutput
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
from cloudops_agent.meta_provider import (
    FakeMetaClient,
    MetaConfigurationError,
    MetaTokenUsage,
)
from cloudops_agent.models import Finding, Severity, SourceType


def iam_finding(finding_id="same-finding-id"):
    return Finding(
        finding_id=finding_id,
        title="IAM sensitive action",
        source_type=SourceType.IAM,
        severity=Severity.MEDIUM,
        description="The deterministic analyzer matched an action.",
        evidence={
            "rule_id": "sensitive-iam-actions",
            "statement_index": 0,
            "Effect": "Allow",
            "Action": ["iam:CreateAccessKey"],
            "Resource": ["*"],
            "matched_actions": ["iam:CreateAccessKey"],
        },
        remediation="Review the permission.",
    )


def cloudtrail_finding():
    return Finding(
        finding_id="trail-finding-id",
        title="CreateAccessKey event",
        source_type=SourceType.CLOUDTRAIL,
        severity=Severity.HIGH,
        description="The deterministic analyzer matched an event.",
        evidence={
            "rule_id": "iam-create-access-key",
            "event": {"eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey"},
        },
        remediation="Review the event.",
    )


def terraform_finding():
    return Finding(
        finding_id="terraform-finding-id",
        title="Public S3 ACL",
        source_type=SourceType.TERRAFORM,
        severity=Severity.HIGH,
        description="A literal ACL is public.",
        evidence={
            "rule_id": "s3-public-acl",
            "configured_values": {"acl": "public-read"},
            "resource_address": "aws_s3_bucket.uploads",
        },
        remediation="Restrict access.",
    )


def valid_response(references):
    finding_ref = next(iter(references.findings))
    return {
        "schema_version": "1",
        "summary": {"text": "The analyzer evidence is summarized.", "references": [finding_ref]},
        "observations": [{
            "claim": "The finding contains the reported analyzer evidence.",
            "basis": "direct_evidence",
            "references": [finding_ref],
            "uncertainty": {"present": False, "note": None},
        }],
        "limitations": [{"text": "The analysis is limited to supplied evidence.", "references": [finding_ref]}],
        "recommendations": [{
            "type": "investigation",
            "priority": "low",
            "action": "Review whether the configuration is expected.",
            "rationale": "The current finding reports a configured value.",
            "references": [finding_ref],
            "uncertainty": {"present": True, "note": "Deployed state was not evaluated."},
        }],
    }


class DisplayRecorder:
    def __init__(self):
        self.text_values = []
        self.labels = []

    def markdown(self, value):
        self.labels.append(value)

    def text(self, value):
        self.text_values.append(value)

    def caption(self, value):
        self.labels.append(value)


def matching_correlation():
    return Correlation(
        correlation_id="stable-correlation-id",
        relationship_type="action_overlap",
        finding_refs=(
            FindingRef("iam-artifact-key", "same-finding-id"),
            FindingRef("trail-artifact-key", "trail-finding-id"),
        ),
        supporting_evidence=(
            EvidenceValue("evidence.matched_actions", "iam:CreateAccessKey"),
            EvidenceValue("evidence.event.eventSource", "iam.amazonaws.com"),
            EvidenceValue("evidence.event.eventName", "CreateAccessKey"),
        ),
        explanation="Both findings reference the same operation type.",
        limitations=("This does not establish identity, authorization, or causation.",),
    )


class InvestigationWorkflowTests(unittest.TestCase):
    def test_finding_builder_uses_artifact_scoped_reference_and_omits_correlations(self):
        selected = iam_finding()
        other = iam_finding()
        artifacts = [
            ("iam-artifact-one", [selected]),
            ("iam-artifact-two", [other]),
        ]
        built = build_finding_investigation(
            FindingRef("iam-artifact-two", other.finding_id),
            artifacts=artifacts,
            correlations=[matching_correlation()],
        )
        self.assertEqual(len(built.payload["findings"]), 1)
        only_finding = built.payload["findings"][0]
        self.assertEqual(only_finding["artifact_ref"], built.payload["artifacts"][0]["artifact_ref"])
        self.assertEqual(built.references.findings[only_finding["finding_ref"]], FindingRef("iam-artifact-two", other.finding_id))
        self.assertEqual(built.payload["correlations"], [])

    def test_terraform_builder_passes_current_artifact_limitations(self):
        finding = terraform_finding()
        artifact_id = "terraform-current-upload"
        limitations = ("Variables and modules were not resolved.",)
        built = build_finding_investigation(
            FindingRef(artifact_id, finding.finding_id),
            artifacts=[(artifact_id, [finding])],
            correlations=[],
            artifact_limitations={artifact_id: limitations},
        )
        self.assertEqual(built.payload["artifacts"][0]["limitations"], list(limitations))

    def test_correlation_builder_includes_exactly_its_two_current_endpoints(self):
        correlation = matching_correlation()
        unrelated = terraform_finding()
        artifacts = [
            ("iam-artifact-key", [iam_finding()]),
            ("trail-artifact-key", [cloudtrail_finding()]),
            ("terraform-artifact", [unrelated]),
        ]
        built = build_correlation_investigation(
            correlation,
            artifacts=artifacts,
            correlations=[correlation],
        )
        self.assertEqual(len(built.payload["findings"]), 2)
        resolved_refs = set(built.references.findings.values())
        self.assertEqual(resolved_refs, set(correlation.finding_refs))
        self.assertEqual(len(built.payload["correlations"]), 1)

        with self.assertRaises(ValueError):
            build_correlation_investigation(
                correlation,
                artifacts=artifacts[:1],
                correlations=[correlation],
            )

    def test_no_provider_request_occurs_without_explicit_action(self):
        built = build_finding_investigation(
            FindingRef("iam-upload", "same-finding-id"),
            artifacts=[("iam-upload", [iam_finding()])],
            correlations=[],
        )
        client = FakeMetaClient()
        factory_calls = []
        execute_investigation_action(
            {}, finding_investigation_key(FindingRef("iam-upload", "same-finding-id")), built,
            requested=False,
            label="IAM: finding",
            client_factory=lambda: factory_calls.append(True) or client,
        )
        self.assertEqual(client.requests, [])
        self.assertEqual(factory_calls, [])

    def test_successful_validated_output_is_stored_and_displayed(self):
        reference = FindingRef("iam-upload", "same-finding-id")
        built = build_finding_investigation(reference, artifacts=[("iam-upload", [iam_finding()])], correlations=[])
        usage = MetaTokenUsage(250, 70, 22)
        sdk_usage = SimpleNamespace(
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            completion_tokens_details=SimpleNamespace(reasoning_tokens=usage.reasoning_tokens),
        )
        client = FakeMetaClient(SimpleCompletion(json.dumps(valid_response(built.references)), usage=sdk_usage))
        state = {"iam-analysis-result-current": {"findings": [iam_finding()]}}
        result_key = finding_investigation_key(reference)
        execute_investigation_action(
            state, result_key, built,
            requested=True,
            label="IAM: IAM sensitive action",
            client_factory=lambda: client,
        )
        record = state[result_key]
        self.assertEqual(record["status"], "success")
        self.assertIsInstance(record["output"], InvestigationOutput)
        self.assertEqual(record["usage"], usage)
        self.assertEqual(len(client.requests), 1)

        view = DisplayRecorder()
        render_token_usage(view, record["usage"])
        render_investigation_output(view, record["output"])
        self.assertIn("The analyzer evidence is summarized.", view.text_values)
        self.assertTrue(any("Citations:" in label for label in view.labels))
        self.assertIn("**Observations**", view.labels)
        self.assertIn("**Limitations**", view.labels)
        self.assertIn("**Recommendations**", view.labels)
        self.assertTrue(any("Investigation · Low priority" in label for label in view.labels))
        self.assertTrue(any("Uncertainty: Deployed state was not evaluated." in value for value in view.text_values))
        self.assertTrue(any("prompt 250" in label and "completion 70" in label and "reasoning 22" in label for label in view.labels))

    def test_provider_and_validation_failures_are_safe_and_keep_deterministic_results(self):
        reference = FindingRef("iam-upload", "same-finding-id")
        finding = iam_finding()
        built = build_finding_investigation(reference, artifacts=[("iam-upload", [finding])], correlations=[])
        result_key = finding_investigation_key(reference)
        deterministic_key = "iam-analysis-result-current"
        state = {deterministic_key: {"findings": [finding]}}

        execute_investigation_action(
            state, result_key, built, requested=True, label="IAM finding",
            client_factory=lambda: FakeMetaClient(exception=RuntimeError("api_key=secret prompt data")),
        )
        failure = state[result_key]
        self.assertEqual(failure["status"], "error")
        self.assertNotIn("secret", failure["message"])
        self.assertNotIn("prompt data", failure["message"])
        self.assertIn(deterministic_key, state)

        invalid = valid_response(built.references)
        invalid["summary"]["references"] = ["f_stale"]
        execute_investigation_action(
            state, result_key, built, requested=True, label="IAM finding",
            client_factory=lambda: FakeMetaClient(SimpleCompletion(json.dumps(invalid))),
        )
        self.assertEqual(state[result_key]["status"], "error")
        self.assertNotIn("output", state[result_key])
        self.assertIn("not displayed", state[result_key]["message"])

    def test_missing_key_error_is_helpful_without_exposing_credentials(self):
        reference = FindingRef("iam-upload", "same-finding-id")
        built = build_finding_investigation(reference, artifacts=[("iam-upload", [iam_finding()])], correlations=[])
        state = {}
        execute_investigation_action(
            state, finding_investigation_key(reference), built,
            requested=True,
            label="IAM finding",
            client_factory=lambda: (_ for _ in ()).throw(MetaConfigurationError("hidden key value")),
        )
        message = next(value["message"] for value in state.values())
        self.assertIn("MODEL_API_KEY", message)
        self.assertNotIn("hidden key value", message)

    def test_results_are_namespaced_by_artifact_and_removed_or_replaced_scopes_clear(self):
        first = FindingRef("iam-upload-one-hash", "same-finding-id")
        second = FindingRef("iam-upload-two-hash", "same-finding-id")
        first_key = finding_investigation_key(first)
        second_key = finding_investigation_key(second)
        self.assertNotEqual(first_key, second_key)

        old_state = {
            first_key: {"status": "success"},
            second_key: {"status": "success"},
        }
        current_artifacts = [("iam-upload-two-hash", [iam_finding()])]
        active = active_investigation_result_keys(current_artifacts, [])
        clear_inactive_investigation_results(old_state, active)
        self.assertNotIn(first_key, old_state)
        self.assertIn(second_key, old_state)

    def test_correlation_results_clear_when_either_endpoint_is_no_longer_current(self):
        correlation = matching_correlation()
        result_key = correlation_investigation_key(correlation)
        state = {result_key: {"status": "success"}}
        current_artifacts = [("iam-artifact-key", [iam_finding()])]
        active = active_investigation_result_keys(current_artifacts, [])
        clear_inactive_investigation_results(state, active)
        self.assertNotIn(result_key, state)

    def test_ordinary_rerun_does_not_repeat_completed_request(self):
        reference = FindingRef("iam-upload", "same-finding-id")
        built = build_finding_investigation(reference, artifacts=[("iam-upload", [iam_finding()])], correlations=[])
        client = FakeMetaClient(SimpleCompletion(json.dumps(valid_response(built.references))))
        state = {}
        key = finding_investigation_key(reference)
        execute_investigation_action(state, key, built, requested=True, label="finding", client_factory=lambda: client)
        previous = state[key]
        execute_investigation_action(state, key, built, requested=False, label="finding", client_factory=lambda: client)
        self.assertEqual(len(client.requests), 1)
        self.assertIs(state[key], previous)

    def test_same_scope_reuses_success_until_explicit_reinvestigation(self):
        reference = FindingRef("iam-upload", "same-finding-id")
        built = build_finding_investigation(reference, artifacts=[("iam-upload", [iam_finding()])], correlations=[])
        client = FakeMetaClient(SimpleCompletion(json.dumps(valid_response(built.references))))
        state = {}
        key = finding_investigation_key(reference)
        execute_investigation_action(
            state, key, built, requested=True, label="finding", client_factory=lambda: client,
        )
        first_output = state[key]["output"]
        self.assertTrue(has_successful_investigation_result(state, key))

        factory_calls = []
        execute_investigation_action(
            state, key, built, requested=True, label="finding",
            client_factory=lambda: factory_calls.append(True) or client,
        )
        self.assertEqual(factory_calls, [])
        self.assertEqual(len(client.requests), 1)
        self.assertIs(state[key]["output"], first_output)

        execute_investigation_action(
            state, key, built, requested=True, label="finding", force=True,
            client_factory=lambda: client,
        )
        self.assertEqual(len(client.requests), 2)
        self.assertIsNot(state[key]["output"], first_output)

    def test_failed_reinvestigation_keeps_only_the_previous_validated_result(self):
        reference = FindingRef("iam-upload", "same-finding-id")
        built = build_finding_investigation(reference, artifacts=[("iam-upload", [iam_finding()])], correlations=[])
        key = finding_investigation_key(reference)
        state = {}
        good_client = FakeMetaClient(SimpleCompletion(json.dumps(valid_response(built.references))))
        execute_investigation_action(
            state, key, built, requested=True, label="finding", client_factory=lambda: good_client,
        )
        previous_output = state[key]["output"]

        execute_investigation_action(
            state, key, built, requested=True, label="finding", force=True,
            client_factory=lambda: FakeMetaClient(exception=RuntimeError("private failure details")),
        )
        self.assertEqual(state[key]["status"], "success")
        self.assertIs(state[key]["output"], previous_output)
        self.assertIn("failed", state[key]["last_reinvestigation_error"])
        self.assertNotIn("private failure details", repr(state[key]))

    def test_failed_or_invalid_attempt_is_not_cached_as_a_success(self):
        reference = FindingRef("iam-upload", "same-finding-id")
        built = build_finding_investigation(reference, artifacts=[("iam-upload", [iam_finding()])], correlations=[])
        key = finding_investigation_key(reference)
        state = {}
        invalid = valid_response(built.references)
        invalid["summary"]["references"] = ["f_unknown"]
        execute_investigation_action(
            state, key, built, requested=True, label="finding",
            client_factory=lambda: FakeMetaClient(SimpleCompletion(json.dumps(invalid))),
        )
        self.assertFalse(has_successful_investigation_result(state, key))

        good_client = FakeMetaClient(SimpleCompletion(json.dumps(valid_response(built.references))))
        execute_investigation_action(
            state, key, built, requested=True, label="finding", client_factory=lambda: good_client,
        )
        self.assertTrue(has_successful_investigation_result(state, key))
        self.assertEqual(len(good_client.requests), 1)

    def test_api_key_like_provider_error_is_not_stored_or_logged(self):
        reference = FindingRef("iam-upload", "same-finding-id")
        built = build_finding_investigation(reference, artifacts=[("iam-upload", [iam_finding()])], correlations=[])
        state = {}
        key = finding_investigation_key(reference)
        execute_investigation_action(
            state, key, built, requested=True, label="finding",
            client_factory=lambda: FakeMetaClient(exception=RuntimeError("MODEL_API_KEY=top-secret")),
        )
        serialized_state = repr(state)
        self.assertNotIn("top-secret", serialized_state)


class SimpleCompletion:
    def __init__(self, content, usage=None):
        from types import SimpleNamespace
        self.choices = [SimpleNamespace(
            finish_reason="stop",
            message=SimpleNamespace(content=content, refusal=None),
        )]
        self.usage = usage


if __name__ == "__main__":
    unittest.main()
