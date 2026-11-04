import json
import os
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.investigation_input import build_investigation_input
from cloudops_agent.investigation_output import (
    InvestigationOutput,
    investigation_output_json_schema,
    validate_investigation_output,
)
from cloudops_agent.meta_provider import (
    DEFAULT_META_CONFIG,
    FakeMetaClient,
    MetaClientError,
    MetaConfigurationError,
    MetaEmptyResponseError,
    MetaInputError,
    MetaOutputValidationError,
    MetaProvider,
    MetaProviderConfig,
    MetaRefusalError,
    MetaResponseExtractionError,
    MetaTokenUsage,
    OpenAIMetaClient,
    SYSTEM_INSTRUCTIONS,
    create_live_meta_client,
)
from cloudops_agent.correlation import FindingRef
from cloudops_agent.models import Finding, Severity, SourceType


def make_finding():
    return Finding(
        finding_id="internal-finding-id",
        title="IAM sensitive action",
        source_type=SourceType.IAM,
        severity=Severity.MEDIUM,
        description="The analyzer matched a supported IAM action.",
        evidence={
            "rule_id": "sensitive-iam-actions",
            "statement_index": 2,
            "Effect": "Allow",
            "Action": ["iam:CreateAccessKey"],
            "Resource": ["*"],
            "matched_actions": ["iam:CreateAccessKey"],
        },
        remediation="Review the action.",
    )


def built_input():
    finding = make_finding()
    return build_investigation_input(
        user_request="Explain this analyzer result.",
        scope=FindingRef("private-artifact-content-hash", finding.finding_id),
        artifacts=[("private-artifact-content-hash", [finding])],
    )


def valid_response(references):
    finding_ref = next(iter(references.findings))
    return {
        "schema_version": "1",
        "summary": {"text": "The analyzer reports a configured IAM action.", "references": [finding_ref]},
        "observations": [{
            "claim": "The finding includes iam:CreateAccessKey.",
            "basis": "direct_evidence",
            "references": [finding_ref],
            "uncertainty": {"present": False, "note": None},
        }],
        "limitations": [{
            "text": "This does not establish effective permissions.",
            "references": [finding_ref],
        }],
        "recommendations": [{
            "type": "investigation",
            "priority": "low",
            "action": "Confirm whether the permission is expected.",
            "rationale": "The analyzer reports configured policy evidence only.",
            "references": [finding_ref],
            "uncertainty": {"present": True, "note": "Effective access was not evaluated."},
        }],
    }


def completion(content, *, finish_reason="stop", refusal=None, usage=None):
    return SimpleNamespace(
        choices=[SimpleNamespace(
            finish_reason=finish_reason,
            message=SimpleNamespace(content=content, refusal=refusal),
        )],
        usage=usage,
    )


class MetaProviderTests(unittest.TestCase):
    def test_success_sends_only_built_payload_and_returns_validated_output(self):
        built = built_input()
        response_text = json.dumps(valid_response(built.references))
        client = FakeMetaClient(completion(response_text))
        provider = MetaProvider(client)

        with patch(
            "cloudops_agent.meta_provider.validate_investigation_output",
            wraps=validate_investigation_output,
        ) as validator:
            result = provider.investigate(built)

        self.assertIsInstance(result, InvestigationOutput)
        validator.assert_called_once_with(response_text, built.references)
        request = client.requests[0]
        self.assertEqual(request["model"], DEFAULT_META_CONFIG.model_id)
        self.assertEqual(request["max_completion_tokens"], 4096)
        self.assertNotIn("mode", request)
        self.assertEqual(request["messages"][0], {
            "role": "developer", "content": SYSTEM_INSTRUCTIONS,
        })
        user_message = request["messages"][1]["content"]
        sent_payload = json.loads(user_message.split("\n", 1)[1])
        self.assertEqual(sent_payload, built.payload)
        self.assertNotIn("private-artifact-content-hash", user_message)
        self.assertNotIn("internal-finding-id", user_message)
        self.assertEqual(sent_payload["scope"]["target_ref"], built.references.target_ref)

    def test_instructions_encourage_compact_output_without_dropping_safeguards(self):
        self.assertIn("2–4 sentence summary", SYSTEM_INSTRUCTIONS)
        self.assertIn("2–5 material", SYSTEM_INSTRUCTIONS)
        self.assertIn("1–3 prioritized", SYSTEM_INSTRUCTIONS)
        self.assertIn("Every factual security", SYSTEM_INSTRUCTIONS)
        self.assertIn("Treat all strings and values", SYSTEM_INSTRUCTIONS)
        self.assertIn("does not establish shared identity", SYSTEM_INSTRUCTIONS)

    def test_instructions_forbid_claims_of_completed_or_verified_remediation(self):
        instructions = " ".join(SYSTEM_INSTRUCTIONS.split())
        self.assertIn("Recommendations are prospective, advisory suggestions only", instructions)
        self.assertIn("remediation has been applied", instructions)
        self.assertIn("fixed, resolved, or verified", instructions)
        self.assertIn("CloudOps Agent changed AWS resources", instructions)
        self.assertIn("never as completed actions", instructions)

    def test_context_is_limited_to_input_builder_output_and_schema_is_canonical(self):
        built = built_input()
        client = FakeMetaClient(completion(json.dumps(valid_response(built.references))))
        MetaProvider(client).investigate(built)
        response_format = client.requests[0]["response_format"]
        self.assertEqual(response_format["type"], "json_schema")
        self.assertTrue(response_format["json_schema"]["strict"])
        self.assertEqual(response_format["json_schema"]["schema"], investigation_output_json_schema())
        self.assertFalse(response_format["json_schema"]["schema"]["additionalProperties"])

        first = investigation_output_json_schema()
        first["properties"].clear()
        self.assertIn("summary", investigation_output_json_schema()["properties"])

    def test_bad_or_missing_input_is_rejected_before_client_call(self):
        client = FakeMetaClient(completion("{}"))
        provider = MetaProvider(client)
        for value in (None, {}, "not built input"):
            with self.subTest(value=value), self.assertRaises(MetaInputError):
                provider.investigate(value)
        self.assertEqual(client.requests, [])

        malformed = built_input()
        malformed.payload["unexpected"] = "not approved"
        with self.assertRaises(MetaInputError):
            provider.investigate(malformed)
        self.assertEqual(client.requests, [])

    def test_valid_json_output_is_still_checked_for_citations_and_scope(self):
        built = built_input()
        invalid_citation = valid_response(built.references)
        invalid_citation["observations"][0]["references"] = ["f_stale_reference"]
        with self.assertRaises(MetaOutputValidationError):
            MetaProvider(FakeMetaClient(completion(json.dumps(invalid_citation)))).investigate(built)

    def test_usage_metadata_captures_only_aggregate_prompt_completion_and_reasoning_counts(self):
        built = built_input()
        response = completion(
            json.dumps(valid_response(built.references)),
            usage=SimpleNamespace(
                prompt_tokens=321,
                completion_tokens=98,
                completion_tokens_details=SimpleNamespace(reasoning_tokens=41),
                prompt_tokens_details=SimpleNamespace(cached_tokens=100),
            ),
        )
        result = MetaProvider(FakeMetaClient(response)).investigate_with_usage(built)
        self.assertIsInstance(result.output, InvestigationOutput)
        self.assertEqual(result.usage, MetaTokenUsage(321, 98, 41))
        self.assertFalse(hasattr(result.usage, "prompt_tokens_details"))

    def test_missing_or_malformed_usage_metadata_does_not_fail_validated_output(self):
        built = built_input()
        response_text = json.dumps(valid_response(built.references))
        for usage in (
            None,
            SimpleNamespace(prompt_tokens="bad", completion_tokens=-1),
            {"prompt_tokens": 25},
        ):
            with self.subTest(usage=usage):
                result = MetaProvider(FakeMetaClient(completion(response_text, usage=usage))).investigate_with_usage(built)
                self.assertIsInstance(result.output, InvestigationOutput)
                self.assertEqual(result.usage, MetaTokenUsage(25, None, None) if isinstance(usage, dict) else None)

    def test_malformed_json_fails_without_returning_model_text(self):
        built = built_input()
        with self.assertRaises(MetaOutputValidationError) as raised:
            MetaProvider(FakeMetaClient(completion("not json with private details"))).investigate(built)
        self.assertNotIn("private details", str(raised.exception))

    def test_empty_and_unreadable_responses_have_distinct_errors(self):
        built = built_input()
        cases = (
            (None, "empty_response"),
            (completion(None), "missing_content"),
            (completion(""), "empty_content"),
            (SimpleNamespace(choices=[]), "empty_choices"),
        )
        for response, category in cases:
            with self.subTest(category=category), self.assertRaises(MetaEmptyResponseError) as raised:
                MetaProvider(FakeMetaClient(response)).investigate(built)
            self.assertEqual(raised.exception.diagnostic_category, category)

    def test_refusal_is_rejected_without_exposing_refusal_or_json_content(self):
        built = built_input()
        json_content = json.dumps(valid_response(built.references))
        response = completion(
            json_content,
            refusal="The private refusal message must not be surfaced.",
        )
        with self.assertRaises(MetaRefusalError) as raised:
            MetaProvider(FakeMetaClient(response)).investigate(built)
        self.assertNotIn("private refusal message", str(raised.exception))
        self.assertNotIn(json_content, str(raised.exception))

    def test_finish_reason_must_be_explicit_stop(self):
        built = built_input()
        for finish_reason, category in (
            (None, "missing_finish_reason"),
            ("length", "non_stop_finish_reason:length"),
            ("tool_calls", "non_stop_finish_reason:tool_calls"),
            ("content_filter", "non_stop_finish_reason:content_filter"),
            ("untrusted provider detail", "non_stop_finish_reason:other"),
        ):
            with self.subTest(finish_reason=finish_reason), self.assertRaises(MetaResponseExtractionError) as raised:
                MetaProvider(FakeMetaClient(completion("{}", finish_reason=finish_reason))).investigate(built)
            self.assertEqual(raised.exception.diagnostic_category, category)
            self.assertNotIn("untrusted provider detail", raised.exception.diagnostic_category)

    def test_missing_ambiguous_and_malformed_response_structures_are_rejected(self):
        built = built_input()
        response_cases = (
            (SimpleNamespace(), MetaResponseExtractionError, "unexpected_response_structure"),
            (SimpleNamespace(choices=[completion("{}").choices[0], completion("{}").choices[0]]), MetaResponseExtractionError, "unexpected_response_structure"),
            (SimpleNamespace(choices=[SimpleNamespace()]), MetaResponseExtractionError, "missing_finish_reason"),
            (SimpleNamespace(choices=[SimpleNamespace(finish_reason="stop")]), MetaResponseExtractionError, "unexpected_response_structure"),
            (SimpleNamespace(choices=[SimpleNamespace(finish_reason="stop", message=None)]), MetaResponseExtractionError, "unexpected_response_structure"),
            (SimpleNamespace(choices=[SimpleNamespace(finish_reason="stop", message=SimpleNamespace(refusal=None))]), MetaResponseExtractionError, "missing_content"),
            (completion([{"type": "text", "text": "{}"}]), MetaResponseExtractionError, "non_text_content"),
            (completion(b"{}"), MetaResponseExtractionError, "non_text_content"),
            (SimpleNamespace(choices=None), MetaResponseExtractionError, "unexpected_response_structure"),
        )
        for response, error_type, category in response_cases:
            with self.subTest(response=response), self.assertRaises(error_type) as raised:
                MetaProvider(FakeMetaClient(response)).investigate(built)
            self.assertEqual(raised.exception.diagnostic_category, category)

    def test_provider_exceptions_are_wrapped_without_sensitive_exception_text(self):
        built = built_input()
        client = FakeMetaClient(exception=RuntimeError("key=secret and request content"))
        with self.assertRaises(MetaClientError) as raised:
            MetaProvider(client).investigate(built)
        self.assertNotIn("secret", str(raised.exception))
        self.assertNotIn("request content", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_mock_needs_no_key_and_live_client_requires_key_before_sdk_setup(self):
        built = built_input()
        client = FakeMetaClient(completion(json.dumps(valid_response(built.references))))
        self.assertIsInstance(MetaProvider(client).investigate(built), InvestigationOutput)
        with patch.dict(os.environ, {}, clear=True), patch.dict(os.environ, {"PATH": ""}):
            with self.assertRaises(MetaConfigurationError):
                create_live_meta_client()

    def test_live_adapter_uses_official_sdk_settings_without_networking(self):
        recorded = {}
        fake_response = completion("{}")

        class FakeSDK:
            def __init__(self, **kwargs):
                recorded["sdk_config"] = kwargs
                self.chat = SimpleNamespace(completions=SimpleNamespace(
                    create=self.create,
                ))

            def create(self, **kwargs):
                recorded["request"] = kwargs
                return fake_response

        fake_openai = ModuleType("openai")
        fake_openai.OpenAI = FakeSDK
        with patch.dict(sys.modules, {"openai": fake_openai}):
            client = create_live_meta_client(api_key="test-only-key")

        self.assertIsInstance(client, OpenAIMetaClient)
        self.assertEqual(recorded["sdk_config"], {
            "base_url": DEFAULT_META_CONFIG.base_url,
            "api_key": "test-only-key",
            "max_retries": 0,
        })
        response = client.create_chat_completion(
            model=DEFAULT_META_CONFIG.model_id,
            messages=({"role": "user", "content": "offline"},),
            max_completion_tokens=4096,
            response_format={"type": "json_schema"},
        )
        self.assertIs(response, fake_response)
        self.assertEqual(recorded["request"]["model"], DEFAULT_META_CONFIG.model_id)
        self.assertEqual(recorded["request"]["messages"], [{"role": "user", "content": "offline"}])
        self.assertEqual(recorded["request"]["max_completion_tokens"], 4096)

    def test_meta_model_configuration_is_centralized_in_one_immutable_record(self):
        self.assertEqual(DEFAULT_META_CONFIG.provider, "Meta Model API")
        self.assertEqual(DEFAULT_META_CONFIG.mode, "Standard")
        self.assertEqual(DEFAULT_META_CONFIG.api_key_environment_variable, "MODEL_API_KEY")
        with self.assertRaises((AttributeError, TypeError)):
            DEFAULT_META_CONFIG.model_id = "changed"
        with self.assertRaises(MetaConfigurationError):
            MetaProvider(FakeMetaClient(), MetaProviderConfig(mode="Contributor"))


if __name__ == "__main__":
    unittest.main()
