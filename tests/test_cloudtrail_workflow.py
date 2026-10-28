import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.analysis_state import (
    analysis_result_key,
    clear_inactive_analysis_results,
)
from cloudops_agent.cloudtrail_analyzer import CloudTrailValidationError, analyze_cloudtrail_events
from cloudops_agent.models import Severity, SourceType
from cloudops_agent.uploads import UploadValidationError, process_upload


def upload_document(document):
    return process_upload(
        "events.json",
        json.dumps(document).encode("utf-8"),
        "CloudTrail logs",
    )


class CloudTrailUploadWorkflowTests(unittest.TestCase):
    def test_uploaded_parsed_document_produces_findings(self):
        uploaded = upload_document(
            {
                "Records": [
                    {
                        "eventSource": "iam.amazonaws.com",
                        "eventName": "CreateAccessKey",
                        "eventID": "event-1",
                        "userIdentity": {"type": "IAMUser", "userName": "demo"},
                    }
                ]
            }
        )

        findings = analyze_cloudtrail_events(uploaded.parsed_document)

        self.assertEqual(len(findings), 1)
        self.assertIs(findings[0].source_type, SourceType.CLOUDTRAIL)
        self.assertIs(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].evidence["eventID"], "event-1")

    def test_valid_upload_with_no_matching_rules_returns_no_findings(self):
        uploaded = upload_document(
            {"Records": [{"eventSource": "s3.amazonaws.com", "eventName": "GetObject"}]}
        )
        self.assertEqual(analyze_cloudtrail_events(uploaded.parsed_document), [])

    def test_invalid_json_is_handled_by_upload_validation(self):
        with self.assertRaises(UploadValidationError):
            process_upload("events.json", b"{broken json", "CloudTrail logs")

    def test_structurally_invalid_event_is_rejected_by_analyzer(self):
        uploaded = upload_document({"Records": [{"eventSource": "iam.amazonaws.com"}]})
        with self.assertRaisesRegex(CloudTrailValidationError, "eventName"):
            analyze_cloudtrail_events(uploaded.parsed_document)

    def test_content_change_and_removal_clear_stale_results(self):
        first_content = b'{"Records": []}'
        changed_content = b'{"Records": [{"eventSource":"s3.amazonaws.com","eventName":"GetObject"}]}'
        first_key = analysis_result_key("cloudtrail", 0, first_content)
        changed_key = analysis_result_key("cloudtrail", 0, changed_content)
        state = {first_key: {"findings": ["old result"]}}

        clear_inactive_analysis_results(state, "cloudtrail", {changed_key})
        self.assertNotIn(first_key, state)

        state[changed_key] = {"findings": []}
        clear_inactive_analysis_results(state, "cloudtrail", set())
        self.assertEqual(state, {})

    def test_other_analyzer_state_is_not_cleared(self):
        state = {"iam-analysis-result-0-old": {"findings": []}}
        clear_inactive_analysis_results(state, "cloudtrail", set())
        self.assertIn("iam-analysis-result-0-old", state)


if __name__ == "__main__":
    unittest.main()
