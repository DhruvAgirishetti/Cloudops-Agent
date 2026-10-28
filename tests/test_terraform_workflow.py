import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.analysis_state import analysis_result_key, clear_inactive_analysis_results
from cloudops_agent.models import SourceType
from cloudops_agent.terraform_analyzer import TerraformValidationError, analyze_terraform
from cloudops_agent.uploads import UploadValidationError, process_upload


class TerraformUploadWorkflowTests(unittest.TestCase):
    def test_uploaded_source_text_is_analyzed_with_filename(self):
        source = 'resource "aws_s3_bucket_acl" "public" { acl = "public-read" }'
        upload = process_upload("storage.tf", source.encode(), "Terraform configuration")
        result = analyze_terraform(upload.source_text, upload.filename)

        self.assertEqual(len(result.findings), 1)
        self.assertIs(result.findings[0].source_type, SourceType.TERRAFORM)
        self.assertEqual(result.findings[0].evidence["filename"], "storage.tf")

    def test_upload_extension_empty_and_size_validation_are_preserved(self):
        for filename, content, expected in (
            ("config.txt", b"resource {}", "Choose a .tf"),
            ("empty.tf", b"", "empty"),
        ):
            with self.subTest(filename=filename):
                with self.assertRaisesRegex(UploadValidationError, expected):
                    process_upload(filename, content, "Terraform configuration")

    def test_malformed_hcl_is_reported_by_analyzer_not_upload_parser(self):
        upload = process_upload(
            "broken.tf", b'resource "aws_s3_bucket" "x" {', "Terraform configuration"
        )
        with self.assertRaisesRegex(TerraformValidationError, "invalid HCL2 syntax"):
            analyze_terraform(upload.source_text, upload.filename)

    def test_replacing_or_removing_terraform_upload_clears_previous_state(self):
        old_content = b'resource "aws_s3_bucket_acl" "x" { acl = "public-read" }'
        new_content = b'resource "aws_s3_bucket_acl" "x" { acl = "private" }'
        old_key = analysis_result_key("terraform", 0, old_content)
        new_key = analysis_result_key("terraform", 0, new_content)
        state = {old_key: {"findings": ["old result"]}}

        clear_inactive_analysis_results(state, "terraform", {new_key})
        self.assertNotIn(old_key, state)
        state[new_key] = {"findings": []}
        clear_inactive_analysis_results(state, "terraform", set())
        self.assertEqual(state, {})


if __name__ == "__main__":
    unittest.main()
