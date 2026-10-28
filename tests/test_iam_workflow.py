import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.iam_analyzer import IAMPolicyValidationError, analyze_iam_policy
from cloudops_agent.uploads import UploadValidationError, process_upload


def upload_policy(policy_text):
    return process_upload("policy.json", policy_text.encode("utf-8"), "AWS IAM policy")


class IAMUploadWorkflowTests(unittest.TestCase):
    def test_uploaded_policy_document_is_passed_to_analyzer(self):
        uploaded = upload_policy(
            '{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}'
        )

        findings = analyze_iam_policy(uploaded.parsed_document)

        self.assertIsInstance(uploaded.parsed_document, dict)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["rule_id"], "unrestricted-wildcard-allow")

    def test_valid_policy_with_no_matching_rule_returns_empty_findings(self):
        uploaded = upload_policy(
            '{"Statement":{"Effect":"Allow","Action":"s3:GetObject",'
            '"Resource":"arn:aws:s3:::example-bucket/*"}}'
        )
        self.assertEqual(analyze_iam_policy(uploaded.parsed_document), [])

    def test_invalid_json_is_rejected_during_upload_validation(self):
        with self.assertRaises(UploadValidationError):
            upload_policy("{not valid JSON")

    def test_invalid_policy_statement_is_rejected_by_analyzer(self):
        uploaded = upload_policy('{"Statement":{"Effect":"Allow","Action":"*"}}')
        with self.assertRaisesRegex(IAMPolicyValidationError, "missing required field 'Resource'"):
            analyze_iam_policy(uploaded.parsed_document)

    def test_unsupported_policy_structure_is_rejected_by_analyzer(self):
        uploaded = upload_policy(
            '{"Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}'
        )
        with self.assertRaisesRegex(IAMPolicyValidationError, "unsupported field 'NotAction'"):
            analyze_iam_policy(uploaded.parsed_document)

    def test_cloudtrail_retains_parsed_document_but_terraform_does_not(self):
        cloudtrail = process_upload(
            "events.json", b'{"eventName":"ConsoleLogin"}', "CloudTrail logs"
        )
        terraform = process_upload(
            "main.tf", b'resource "aws_s3_bucket" "logs" {}', "Terraform configuration"
        )
        self.assertEqual(cloudtrail.parsed_document, {"eventName": "ConsoleLogin"})
        self.assertIsNone(terraform.parsed_document)


if __name__ == "__main__":
    unittest.main()
