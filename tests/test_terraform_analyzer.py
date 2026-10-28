import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.models import Severity, SourceType
from cloudops_agent.terraform_analyzer import (
    TerraformValidationError,
    analyze_terraform,
)


class TerraformAnalyzerTests(unittest.TestCase):
    def test_public_s3_acl_reports_literal_and_context(self):
        result = analyze_terraform(
            'resource "aws_s3_bucket_acl" "assets" { acl = "public-read-write" }',
            "storage.tf",
        )
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertIs(finding.source_type, SourceType.TERRAFORM)
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertEqual(finding.evidence["filename"], "storage.tf")
        self.assertEqual(finding.evidence["resource_address"], "aws_s3_bucket_acl.assets")
        self.assertEqual(finding.evidence["configured_values"], {"acl": "public-read-write"})
        self.assertIn("does not establish effective or deployed public access", finding.description)
        self.assertIn("public-access controls separately", finding.remediation)

    def test_both_supported_public_acl_values_match(self):
        for acl in ("public-read", "public-read-write"):
            with self.subTest(acl=acl):
                source = f'resource "aws_s3_bucket_acl" "assets" {{ acl = "{acl}" }}'
                self.assertEqual(len(analyze_terraform(source).findings), 1)

    def test_private_acl_and_other_resource_types_do_not_match(self):
        source = '''
resource "aws_s3_bucket_acl" "private" { acl = "private" }
resource "aws_s3_bucket" "not_an_acl_rule" { acl = "public-read" }
'''
        self.assertEqual(analyze_terraform(source).findings, [])

    def test_dynamic_s3_acl_is_a_limitation_not_a_finding(self):
        result = analyze_terraform(
            'resource "aws_s3_bucket_acl" "assets" { acl = var.bucket_acl }'
        )
        self.assertEqual(result.findings, [])
        self.assertTrue(any("ACL value" in item and "skipped" in item for item in result.limitations))

    def test_explicit_false_public_access_settings_are_aggregated(self):
        result = analyze_terraform(
            '''resource "aws_s3_bucket_public_access_block" "assets" {
  block_public_acls = false
  block_public_policy = false
  ignore_public_acls = true
  restrict_public_buckets = true
}'''
        )
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertIs(finding.severity, Severity.MEDIUM)
        self.assertEqual(
            finding.evidence["configured_values"],
            {"block_public_acls": False, "block_public_policy": False},
        )
        self.assertIn("does not prove the bucket is publicly accessible", finding.description)

    def test_true_or_omitted_public_access_settings_do_not_match(self):
        result = analyze_terraform(
            '''resource "aws_s3_bucket_public_access_block" "assets" {
  block_public_acls = true
  restrict_public_buckets = true
}'''
        )
        self.assertEqual(result.findings, [])

    def test_dynamic_setting_is_limited_but_other_false_setting_is_detected(self):
        result = analyze_terraform(
            '''resource "aws_s3_bucket_public_access_block" "assets" {
  block_public_acls = var.block_acls
  restrict_public_buckets = false
}'''
        )
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            result.findings[0].evidence["configured_values"],
            {"restrict_public_buckets": False},
        )
        self.assertTrue(any("block_public_acls" in item for item in result.limitations))

    def test_inline_security_group_detects_ipv4_and_ipv6_admin_ingress(self):
        sources = (
            '''resource "aws_security_group" "ssh" {
  ingress { protocol = "tcp" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }
}''',
            '''resource "aws_security_group" "rdp" {
  ingress { protocol = "tcp" from_port = 3389 to_port = 3389 ipv6_cidr_blocks = ["::/0"] }
}''',
        )
        for source in sources:
            with self.subTest(source=source):
                result = analyze_terraform(source)
                self.assertEqual(len(result.findings), 1)
                self.assertIs(result.findings[0].severity, Severity.HIGH)
                self.assertEqual(result.findings[0].evidence["configured_values"]["protocol"], "tcp")

    def test_all_protocol_public_ingress_matches_without_port_values(self):
        result = analyze_terraform(
            '''resource "aws_security_group" "open" {
  ingress { protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}'''
        )
        self.assertEqual(len(result.findings), 1)
        self.assertIn("allows all protocols", result.findings[0].description)

    def test_numeric_tcp_protocol_and_dynamic_protocol_are_handled_explicitly(self):
        numeric_tcp = analyze_terraform(
            '''resource "aws_security_group" "numeric_tcp" {
  ingress { protocol = "6" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }
}'''
        )
        self.assertEqual(len(numeric_tcp.findings), 1)

        dynamic_protocol = analyze_terraform(
            '''resource "aws_security_group" "dynamic_protocol" {
  ingress { protocol = var.protocol from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }
}'''
        )
        self.assertEqual(dynamic_protocol.findings, [])
        self.assertTrue(any("protocol" in item for item in dynamic_protocol.limitations))

    def test_restricted_cidr_non_admin_port_and_udp_do_not_match(self):
        source = '''resource "aws_security_group" "safe_examples" {
  ingress { protocol = "tcp" from_port = 22 to_port = 22 cidr_blocks = ["203.0.113.0/24"] }
  ingress { protocol = "tcp" from_port = 80 to_port = 80 cidr_blocks = ["0.0.0.0/0"] }
  ingress { protocol = "udp" from_port = 3389 to_port = 3389 cidr_blocks = ["0.0.0.0/0"] }
}'''
        self.assertEqual(analyze_terraform(source).findings, [])

    def test_standalone_security_group_ingress_is_reported_as_unsupported(self):
        result = analyze_terraform(
            '''resource "aws_vpc_security_group_ingress_rule" "ssh" {
  cidr_ipv4 = "0.0.0.0/0"
  from_port = 22
  to_port = 22
  ip_protocol = "tcp"
}'''
        )
        self.assertEqual(result.findings, [])
        self.assertTrue(any("Standalone ingress rule" in item for item in result.limitations))

    def test_computed_ingress_values_are_reported_without_blocking_other_resources(self):
        source = '''resource "aws_security_group" "dynamic" {
  ingress { protocol = "tcp" from_port = 22 to_port = 22 cidr_blocks = var.admin_cidrs }
}
resource "aws_s3_bucket_acl" "public" { acl = "public-read" }
'''
        result = analyze_terraform(source)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].evidence["resource_address"], "aws_s3_bucket_acl.public")
        self.assertTrue(any("cidr_blocks" in item for item in result.limitations))

    def test_dynamic_ingress_block_is_limited_and_static_ingress_still_checked(self):
        source = '''resource "aws_security_group" "mixed" {
  dynamic "ingress" {
    for_each = var.rules
    content { protocol = "tcp" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }
  }
  ingress { protocol = "tcp" from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }
}'''
        result = analyze_terraform(source)
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(any("Dynamic blocks" in item for item in result.limitations))

    def test_comments_and_string_values_that_look_like_resources_are_ignored(self):
        source = '''
# resource "aws_s3_bucket_acl" "comment" { acl = "public-read" }
resource "aws_s3_bucket" "text" {
  tags = { note = "resource \\"aws_s3_bucket_acl\\" \\"fake\\" { acl = \\"public-read\\" }" }
}
'''
        self.assertEqual(analyze_terraform(source).findings, [])

    def test_findings_from_multiple_resources_have_stable_distinct_ids(self):
        source = '''
resource "aws_s3_bucket_acl" "one" { acl = "public-read" }
resource "aws_s3_bucket_acl" "two" { acl = "public-read-write" }
'''
        first = analyze_terraform(source, "storage.tf").findings
        second = analyze_terraform(source, "storage.tf").findings
        self.assertEqual([item.finding_id for item in first], [item.finding_id for item in second])
        self.assertEqual(len({item.finding_id for item in first}), 2)

    def test_existing_terraform_sample_has_no_matching_rules(self):
        sample_path = Path(__file__).resolve().parents[1] / "test_samples" / "test_terraform.tf"
        result = analyze_terraform(sample_path.read_text(encoding="utf-8"), sample_path.name)
        self.assertEqual(result.findings, [])

    def test_malformed_hcl_raises_without_returning_partial_findings(self):
        source = '''
resource "aws_s3_bucket_acl" "public" { acl = "public-read" }
resource "aws_security_group" "broken" {
  ingress { protocol = "tcp" from_port = 22
'''
        with self.assertRaisesRegex(TerraformValidationError, "invalid HCL2 syntax"):
            analyze_terraform(source)


if __name__ == "__main__":
    unittest.main()
