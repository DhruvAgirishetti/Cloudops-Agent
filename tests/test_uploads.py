import json

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.uploads import MAX_UPLOAD_BYTES, UploadValidationError, process_upload


class UploadTests(unittest.TestCase):
    def test_cloudtrail_upload_reports_record_count_without_security_claims(self):
        content = json.dumps({"Records": [{"eventName": "ConsoleLogin"}]}).encode()
        result = process_upload("events.JSON", content, "CloudTrail logs")
        self.assertEqual(result.filename, "events.JSON")
        self.assertIn("1 record(s)", result.summary)
        self.assertIn("No security checks", result.summary)

    def test_iam_policy_accepts_single_statement_object(self):
        content = json.dumps({"Statement": {"Effect": "Allow"}}).encode()
        result = process_upload("policy.json", content, "AWS IAM policy")
        self.assertIn("1 statement(s)", result.summary)

    def test_terraform_summary_counts_blocks_without_execution(self):
        content = b'provider "aws" {}\nresource "aws_s3_bucket" "logs" {}'
        result = process_upload("main.tf", content, "Terraform configuration")
        self.assertIn("1 resource block(s)", result.summary)
        self.assertIn("1 AWS provider block(s)", result.summary)
        self.assertIn("not executed", result.summary)

    def test_invalid_uploads_are_rejected(self):
        invalid_uploads = [
            ("policy.txt", b"{}", "AWS IAM policy", "Choose a .json"),
            ("empty.json", b"", "CloudTrail logs", "empty"),
            ("large.json", b"x" * (MAX_UPLOAD_BYTES + 1), "CloudTrail logs", "5 MB"),
            ("broken.json", b"not json", "AWS IAM policy", "valid UTF-8 JSON"),
            ("wrong.json", b"[]", "AWS IAM policy", "top level"),
            ("policy.json", b"{}", "AWS IAM policy", "Statement field"),
        ]
        for filename, content, input_type, message in invalid_uploads:
            with self.subTest(filename=filename):
                with self.assertRaisesRegex(UploadValidationError, message):
                    process_upload(filename, content, input_type)

    def test_filename_paths_are_reduced_to_the_basename(self):
        result = process_upload(r"C:\uploads\events.json", b'{"Records": []}', "CloudTrail logs")
        self.assertEqual(result.filename, "events.json")


if __name__ == "__main__":
    unittest.main()
