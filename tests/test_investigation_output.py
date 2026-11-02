import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.correlation import Correlation, EvidenceValue, FindingRef
from cloudops_agent.investigation_input import build_investigation_input
from cloudops_agent.investigation_output import (
    InvestigationOutputValidationError,
    MAX_OBSERVATIONS,
    MAX_RESPONSE_BYTES,
    Observation,
    Recommendation,
    Uncertainty,
    validate_investigation_output,
)
from cloudops_agent.models import Finding, Severity, SourceType


def make_finding(finding_id, source=SourceType.IAM):
    return Finding(
        finding_id=finding_id,
        title="IAM sensitive action",
        source_type=source,
        severity=Severity.MEDIUM,
        description="A static policy rule matched.",
        evidence={
            "rule_id": "sensitive-iam-actions",
            "statement_index": 1,
            "Effect": "Allow",
            "Action": ["iam:CreateAccessKey"],
            "Resource": ["*"],
            "matched_actions": ["iam:CreateAccessKey"],
        },
        remediation="Review the action.",
    )


def finding_request(finding_id="finding-internal", artifact_id="artifact-hash"):
    finding = make_finding(finding_id)
    return build_investigation_input(
        user_request="Explain the finding.",
        scope=FindingRef(artifact_id, finding_id),
        artifacts=[(artifact_id, [finding])],
    )


def correlation_request():
    iam = make_finding("iam-internal", SourceType.IAM)
    trail = Finding(
        finding_id="trail-internal",
        title="CreateAccessKey event",
        source_type=SourceType.CLOUDTRAIL,
        severity=Severity.HIGH,
        description="An IAM event matched.",
        evidence={
            "rule_id": "iam-create-access-key",
            "event": {"eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey"},
        },
        remediation="Review the event.",
    )
    iam_ref = FindingRef("iam-hash", iam.finding_id)
    trail_ref = FindingRef("trail-hash", trail.finding_id)
    correlation = Correlation(
        correlation_id="internal-correlation-id",
        relationship_type="action_overlap",
        finding_refs=(iam_ref, trail_ref),
        supporting_evidence=(
            EvidenceValue("evidence.matched_actions", "iam:CreateAccessKey"),
            EvidenceValue("evidence.event.eventSource", "iam.amazonaws.com"),
            EvidenceValue("evidence.event.eventName", "CreateAccessKey"),
        ),
        explanation="Both findings reference the same operation type.",
        limitations=("Does not establish authorization or causation.",),
    )
    return build_investigation_input(
        user_request="Explain the correlation.",
        scope=correlation,
        artifacts=[("iam-hash", [iam]), ("trail-hash", [trail])],
        correlations=[correlation],
    )


def valid_response(references, *, summary_refs=None, observation_refs=None, recommendation_refs=None):
    finding_ref = next(iter(references.findings))
    ref = finding_ref
    return {
        "schema_version": "1",
        "summary": {
            "text": "The supplied analyzer result reports a sensitive action.",
            "references": summary_refs if summary_refs is not None else [ref],
        },
        "observations": [{
            "claim": "The finding records iam:CreateAccessKey.",
            "basis": "direct_evidence",
            "references": observation_refs if observation_refs is not None else [ref],
            "uncertainty": {"present": False, "note": None},
        }],
        "limitations": [{"text": "The static result does not prove effective access.", "references": [ref]}],
        "recommendations": [{
            "type": "investigation",
            "priority": "low",
            "action": "Review whether this permission is expected.",
            "rationale": "The analyzer reports the configured action only.",
            "references": recommendation_refs if recommendation_refs is not None else [ref],
            "uncertainty": {"present": True, "note": "Effective permissions were not evaluated."},
        }],
    }


class InvestigationOutputTests(unittest.TestCase):
    def test_valid_output_passes_and_returns_structured_dataclasses(self):
        built = finding_request()
        result = validate_investigation_output(json.dumps(valid_response(built.references)), built.references)
        self.assertEqual(result.schema_version, "1")
        self.assertEqual(len(result.observations), 1)
        self.assertIsInstance(result.observations[0], Observation)
        self.assertEqual(result.observations[0].uncertainty, Uncertainty(False, None))
        self.assertIsInstance(result.recommendations[0], Recommendation)
        self.assertEqual(result.recommendations[0].uncertainty.present, True)

    def test_bytes_json_is_supported(self):
        built = finding_request()
        raw = json.dumps(valid_response(built.references)).encode("utf-8")
        self.assertEqual(validate_investigation_output(raw, built.references).schema_version, "1")

    def test_invalid_json_and_non_object_top_level_fail(self):
        built = finding_request()
        for raw in ("{bad", "[]", "null", "42", '"text"'):
            with self.subTest(raw=raw), self.assertRaises(InvestigationOutputValidationError):
                validate_investigation_output(raw, built.references)

    def test_missing_and_unexpected_properties_fail(self):
        built = finding_request()
        missing = valid_response(built.references)
        del missing["observations"]
        with self.assertRaisesRegex(InvestigationOutputValidationError, "missing required"):
            validate_investigation_output(json.dumps(missing), built.references)

        extra = valid_response(built.references)
        extra["internal_finding_id"] = "must not be accepted"
        with self.assertRaisesRegex(InvestigationOutputValidationError, "unexpected"):
            validate_investigation_output(json.dumps(extra), built.references)

        extra_nested = valid_response(built.references)
        extra_nested["observations"][0]["confidence"] = 0.99
        with self.assertRaisesRegex(InvestigationOutputValidationError, "unexpected"):
            validate_investigation_output(json.dumps(extra_nested), built.references)

    def test_invalid_enums_types_and_empty_strings_fail(self):
        built = finding_request()
        invalid_cases = []

        value = valid_response(built.references)
        value["observations"][0]["basis"] = "guess"
        invalid_cases.append(value)
        value = valid_response(built.references)
        value["recommendations"][0]["type"] = "execution"
        invalid_cases.append(value)
        value = valid_response(built.references)
        value["recommendations"][0]["priority"] = "urgent"
        invalid_cases.append(value)
        value = valid_response(built.references)
        value["summary"]["text"] = 4
        invalid_cases.append(value)
        value = valid_response(built.references)
        value["observations"] = "not a list"
        invalid_cases.append(value)
        value = valid_response(built.references)
        value["recommendations"][0]["action"] = " \t "
        invalid_cases.append(value)

        for response in invalid_cases:
            with self.subTest(response=response), self.assertRaises(InvestigationOutputValidationError):
                validate_investigation_output(json.dumps(response), built.references)

    def test_wrong_schema_version_fails(self):
        built = finding_request()
        response = valid_response(built.references)
        response["schema_version"] = "2"
        with self.assertRaisesRegex(InvestigationOutputValidationError, "schema_version"):
            validate_investigation_output(json.dumps(response), built.references)

    def test_oversized_response_strings_and_lists_fail(self):
        built = finding_request()
        with self.assertRaisesRegex(InvestigationOutputValidationError, "maximum allowed size"):
            validate_investigation_output(b" " * (MAX_RESPONSE_BYTES + 1), built.references)

        response = valid_response(built.references)
        response["summary"]["text"] = "x" * 2001
        with self.assertRaisesRegex(InvestigationOutputValidationError, "maximum length"):
            validate_investigation_output(json.dumps(response), built.references)

        response = valid_response(built.references)
        response["observations"] = [copy.deepcopy(response["observations"][0])] * (MAX_OBSERVATIONS + 1)
        with self.assertRaisesRegex(InvestigationOutputValidationError, "maximum number"):
            validate_investigation_output(json.dumps(response), built.references)

    def test_uncertainty_structure_and_consistency_are_enforced(self):
        built = finding_request()
        invalid = (
            {"present": "false", "note": None},
            {"present": True, "note": None},
            {"present": True, "note": "  "},
            {"present": False, "note": "no uncertainty"},
            {"present": False, "note": None, "extra": "field"},
        )
        for uncertainty in invalid:
            with self.subTest(uncertainty=uncertainty):
                response = valid_response(built.references)
                response["observations"][0]["uncertainty"] = uncertainty
                with self.assertRaises(InvestigationOutputValidationError):
                    validate_investigation_output(json.dumps(response), built.references)

    def test_uncited_observations_recommendations_and_summary_fail(self):
        built = finding_request()
        cases = (
            ("observations", 0, "references"),
            ("recommendations", 0, "references"),
        )
        for section, index, key in cases:
            with self.subTest(section=section):
                response = valid_response(built.references)
                response[section][index][key] = []
                with self.assertRaisesRegex(InvestigationOutputValidationError, "at least one"):
                    validate_investigation_output(json.dumps(response), built.references)
        response = valid_response(built.references)
        response["summary"]["references"] = []
        with self.assertRaises(InvestigationOutputValidationError):
            validate_investigation_output(json.dumps(response), built.references)

    def test_unknown_internal_stale_and_cross_request_citations_fail(self):
        first = finding_request("first-id", "first-hash")
        second = finding_request("second-id", "second-hash")
        second_ref = next(iter(second.references.findings))
        response = valid_response(first.references)
        response["observations"][0]["references"] = ["f_unknown_or_stale"]
        with self.assertRaisesRegex(InvestigationOutputValidationError, "unknown or out-of-scope"):
            validate_investigation_output(json.dumps(response), first.references)

        response = valid_response(first.references)
        response["observations"][0]["references"] = [second_ref]
        with self.assertRaises(InvestigationOutputValidationError):
            validate_investigation_output(json.dumps(response), first.references)

        response = valid_response(first.references)
        response["observations"][0]["references"] = ["first-id"]
        with self.assertRaises(InvestigationOutputValidationError):
            validate_investigation_output(json.dumps(response), first.references)

    def test_finding_scope_rejects_unrelated_finding_and_correlation_refs(self):
        built = finding_request()
        unrelated = next(iter(finding_request("other-id", "other-hash").references.findings))
        response = valid_response(built.references)
        response["recommendations"][0]["references"] = [unrelated]
        with self.assertRaises(InvestigationOutputValidationError):
            validate_investigation_output(json.dumps(response), built.references)

        response = valid_response(built.references)
        response["summary"]["references"] = ["c_not-in-scope"]
        with self.assertRaises(InvestigationOutputValidationError):
            validate_investigation_output(json.dumps(response), built.references)

    def test_correlation_scope_allows_only_selected_correlation_and_endpoints(self):
        built = correlation_request()
        response = valid_response(built.references)
        correlation_ref = next(iter(built.references.correlations))
        endpoint_refs = list(built.references.findings)
        response["summary"]["references"] = [correlation_ref]
        response["observations"][0]["references"] = [endpoint_refs[0], correlation_ref]
        response["recommendations"][0]["references"] = [endpoint_refs[1]]
        result = validate_investigation_output(json.dumps(response), built.references)
        self.assertEqual(len(result.observations[0].references), 2)

        unrelated = next(iter(finding_request("other", "other-artifact").references.findings))
        response["observations"][0]["references"] = [unrelated]
        with self.assertRaises(InvestigationOutputValidationError):
            validate_investigation_output(json.dumps(response), built.references)

    def test_valid_citation_does_not_claim_semantic_correctness(self):
        built = finding_request()
        response = valid_response(built.references)
        response["observations"][0]["claim"] = "This proves the uploaded environment is compromised."
        validated = validate_investigation_output(json.dumps(response), built.references)
        self.assertEqual(
            validated.observations[0].claim,
            "This proves the uploaded environment is compromised.",
        )


if __name__ == "__main__":
    unittest.main()
