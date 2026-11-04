import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.correlation import correlate_findings
from cloudops_agent.cloudtrail_analyzer import analyze_cloudtrail_events
from cloudops_agent.iam_analyzer import analyze_iam_policy
from cloudops_agent.models import Finding, Severity, SourceType


def finding(finding_id, source, evidence):
    return Finding(
        finding_id=finding_id,
        title="Example finding",
        source_type=source,
        severity=Severity.MEDIUM,
        description="Example description",
        evidence=evidence,
        remediation="Review the finding.",
    )


def iam(action="iam:CreateAccessKey"):
    return finding("same-id", SourceType.IAM, {"matched_actions": [action]})


def cloudtrail(source="iam.amazonaws.com", name="CreateAccessKey"):
    return finding("same-id", SourceType.CLOUDTRAIL, {
        "event": {"eventSource": source, "eventName": name},
    })


def network_finding(finding_id, source, evidence):
    return finding(finding_id, source, evidence)


def network_inputs():
    iam_finding = network_finding("iam-network", SourceType.IAM, {
        "rule_id": "sensitive-iam-actions", "Effect": "Allow",
        "Action": ["ec2:AuthorizeSecurityGroupIngress"],
        "matched_actions": ["ec2:AuthorizeSecurityGroupIngress"],
    })
    cloudtrail_finding = network_finding("ct-network", SourceType.CLOUDTRAIL, {
        "rule_id": "ec2-authorize-security-group-ingress-public-admin",
        "event": {"eventSource": "ec2.amazonaws.com", "eventName": "AuthorizeSecurityGroupIngress"},
        "matched_permissions": [{"protocol": "tcp", "admin_ports": [22], "public_cidrs": ["0.0.0.0/0"]}],
    })
    terraform_finding = network_finding("tf-network", SourceType.TERRAFORM, {
        "rule_id": "security-group-public-admin-ingress",
        "configured_values": {"protocol": "tcp", "from_port": 22, "to_port": 22, "public_cidrs": ["0.0.0.0/0"]},
        "resource_address": "aws_security_group.example.ingress[0]",
    })
    return iam_finding, cloudtrail_finding, terraform_finding


class CorrelationTests(unittest.TestCase):
    def test_exact_action_overlap_emits_cautious_correlation(self):
        original_iam = iam()
        original_trail = cloudtrail()
        result = correlate_findings([
            ("policy-upload", [original_iam]),
            ("event-upload", [original_trail]),
        ])
        self.assertEqual(len(result), 1)
        correlation = result[0]
        self.assertEqual(correlation.relationship_type, "action_overlap")
        self.assertEqual(
            [(ref.artifact_id, ref.finding_id) for ref in correlation.finding_refs],
            [("policy-upload", "same-id"), ("event-upload", "same-id")],
        )
        self.assertEqual(
            [(item.path, item.value) for item in correlation.supporting_evidence],
            [
                ("evidence.matched_actions", "iam:CreateAccessKey"),
                ("evidence.event.eventSource", "iam.amazonaws.com"),
                ("evidence.event.eventName", "CreateAccessKey"),
            ],
        )
        self.assertIn("evidence overlap only", correlation.explanation)
        self.assertIn("authorization", correlation.limitations[0])
        self.assertIn("causation", correlation.limitations[0])
        self.assertEqual(original_iam.evidence["matched_actions"], ["iam:CreateAccessKey"])
        self.assertEqual(original_trail.evidence["event"]["eventName"], "CreateAccessKey")

    def test_mismatch_missing_and_malformed_evidence_do_not_match(self):
        cases = [
            [("i", [iam("iam:DeleteAccessKey")]), ("c", [cloudtrail()])],
            [("i", [finding("i", SourceType.IAM, {})]), ("c", [cloudtrail()])],
            [("i", [finding("i", SourceType.IAM, {"matched_actions": "iam:CreateAccessKey"})]), ("c", [cloudtrail()])],
            [("i", [iam()]), ("c", [finding("c", SourceType.CLOUDTRAIL, {"event": []})])],
            [("i", [iam()]), ("c", [cloudtrail(source="IAM.amazonaws.com")])],
            [("i", [iam()]), ("c", [cloudtrail(name="createaccesskey")])],
        ]
        for artifacts in cases:
            with self.subTest(artifacts=artifacts):
                self.assertEqual(correlate_findings(artifacts), ())

    def test_wildcards_do_not_expand_to_supported_action(self):
        for wildcard in ("*", "iam:*", "iam:Create*"):
            with self.subTest(wildcard=wildcard):
                self.assertEqual(correlate_findings([
                    ("i", [iam(wildcard)]), ("c", [cloudtrail()]),
                ]), ())

    def test_multiple_candidates_on_either_side_are_ambiguous(self):
        self.assertEqual(correlate_findings([
            ("i1", [iam()]), ("i2", [iam()]), ("c", [cloudtrail()]),
        ]), ())
        self.assertEqual(correlate_findings([
            ("i", [iam()]), ("c1", [cloudtrail()]), ("c2", [cloudtrail()]),
        ]), ())

    def test_duplicate_identical_references_are_deduplicated(self):
        self.assertEqual(len(correlate_findings([
            ("i", [iam(), iam()]), ("c", [cloudtrail(), cloudtrail()]),
        ])), 1)

    def test_conflicting_records_for_one_reference_are_excluded(self):
        self.assertEqual(correlate_findings([
            ("i", [iam(), iam("iam:DeleteAccessKey")]),
            ("c", [cloudtrail()]),
        ]), ())

    def test_same_finding_id_in_distinct_artifacts_remains_distinct(self):
        self.assertEqual(correlate_findings([
            ("i1", [iam()]), ("i2", [iam()]), ("c", [cloudtrail()]),
        ]), ())

    def test_terraform_findings_are_ignored(self):
        terraform = finding("tf", SourceType.TERRAFORM, {
            "matched_actions": ["iam:CreateAccessKey"],
            "event": {"eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey"},
        })
        self.assertEqual(correlate_findings([
            ("tf", [terraform]), ("i", [iam()]), ("c", [cloudtrail()]),
        ])[0].relationship_type, "action_overlap")

    def test_id_is_independent_of_artifact_and_finding_order(self):
        i1, c = iam(), cloudtrail()
        irrelevant = finding("other-id", SourceType.IAM, {
            "matched_actions": ["iam:DeleteAccessKey"],
        })
        first = correlate_findings([("policy", [i1]), ("event", [c])])
        second = correlate_findings([("event", [c]), ("policy", [irrelevant, i1])])
        self.assertEqual(first[0].correlation_id, second[0].correlation_id)

    def test_three_source_correlation_requires_exact_action_and_shared_configuration_pattern(self):
        iam_finding, cloudtrail_finding, terraform_finding = network_inputs()
        result = correlate_findings([
            ("tf-artifact", [terraform_finding]),
            ("ct-artifact", [cloudtrail_finding]),
            ("iam-artifact", [iam_finding]),
        ])
        self.assertEqual(len(result), 1)
        correlation = result[0]
        self.assertEqual(correlation.relationship_type, "configuration_pattern_overlap")
        self.assertEqual([ref.artifact_id for ref in correlation.finding_refs], [
            "iam-artifact", "ct-artifact", "tf-artifact",
        ])
        self.assertEqual(
            [(item.path, item.value) for item in correlation.supporting_evidence],
            [
                ("evidence.Action", "ec2:AuthorizeSecurityGroupIngress"),
                ("evidence.event.eventName", "AuthorizeSecurityGroupIngress"),
                ("evidence.matched_permissions[0].protocol", "tcp"),
                ("evidence.matched_permissions[0].admin_ports[0]", "22"),
                ("evidence.matched_permissions[0].public_cidrs[0]", "0.0.0.0/0"),
                ("evidence.configured_values.protocol", "tcp"),
                ("evidence.configured_values.from_port", "22"),
                ("evidence.configured_values.to_port", "22"),
                ("evidence.configured_values.public_cidrs[0]", "0.0.0.0/0"),
            ],
        )
        self.assertIn("configuration-pattern overlap", correlation.explanation)
        self.assertIn("does not identify", correlation.limitations[0])

    def test_analyzer_outputs_support_the_three_source_correlation(self):
        iam_finding = analyze_iam_policy({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": "ec2:AuthorizeSecurityGroupIngress", "Resource": "*",
            }],
        })[-1]
        cloudtrail_finding = analyze_cloudtrail_events({
            "eventSource": "ec2.amazonaws.com", "eventName": "AuthorizeSecurityGroupIngress",
            "eventID": "network-event",
            "requestParameters": {"ipPermissions": {"items": [{
                "ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
            }]}},
        })[0]
        _, _, terraform_finding = network_inputs()
        result = correlate_findings([
            ("iam-file", [iam_finding]), ("event-file", [cloudtrail_finding]),
            ("terraform-file", [terraform_finding]),
        ])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].relationship_type, "configuration_pattern_overlap")

    def test_terraform_all_protocol_public_rule_supports_admin_port_pattern(self):
        iam_finding, cloudtrail_finding, terraform_finding = network_inputs()
        terraform_finding = finding("tf-network-all", SourceType.TERRAFORM, {
            "rule_id": "security-group-public-admin-ingress",
            "configured_values": {"protocol": "-1", "public_cidrs": ["0.0.0.0/0"]},
        })
        result = correlate_findings([
            ("i", [iam_finding]), ("c", [cloudtrail_finding]), ("t", [terraform_finding]),
        ])
        self.assertEqual(len(result), 1)
        evidence = {(item.path, item.value) for item in result[0].supporting_evidence}
        self.assertIn(("evidence.configured_values.protocol", "-1"), evidence)
        self.assertIn(("evidence.configured_values.public_cidrs[0]", "0.0.0.0/0"), evidence)

    def test_three_source_partial_unrelated_and_wildcard_matches_are_rejected(self):
        iam_finding, cloudtrail_finding, terraform_finding = network_inputs()
        cases = (
            [("i", [iam_finding]), ("c", [cloudtrail_finding])],
            [("i", [iam_finding]), ("c", [cloudtrail_finding]), ("t", [finding("other", SourceType.TERRAFORM, {})])],
            [("i", [finding("wild", SourceType.IAM, {**iam_finding.evidence, "Action": ["ec2:*"]})]), ("c", [cloudtrail_finding]), ("t", [terraform_finding])],
            [("i", [iam_finding]), ("c", [cloudtrail_finding]), ("t", [finding("restricted", SourceType.TERRAFORM, {**terraform_finding.evidence, "configured_values": {"protocol": "tcp", "from_port": 22, "to_port": 22, "public_cidrs": ["203.0.113.0/24"]}})])],
        )
        for artifacts in cases:
            with self.subTest(artifacts=artifacts):
                self.assertEqual(correlate_findings(artifacts), ())

    def test_three_source_id_and_output_are_stable_under_input_reordering(self):
        iam_finding, cloudtrail_finding, terraform_finding = network_inputs()
        first = correlate_findings([("i", [iam_finding]), ("c", [cloudtrail_finding]), ("t", [terraform_finding])])
        second = correlate_findings([("t", [terraform_finding]), ("c", [cloudtrail_finding]), ("i", [iam_finding])])
        self.assertEqual(first, second)

    def test_three_source_duplicates_are_deduplicated_and_conflicts_excluded(self):
        iam_finding, cloudtrail_finding, terraform_finding = network_inputs()
        repeated = correlate_findings([
            ("i", [iam_finding, iam_finding]),
            ("c", [cloudtrail_finding, cloudtrail_finding]),
            ("t", [terraform_finding, terraform_finding]),
        ])
        self.assertEqual(len(repeated), 1)
        conflict = finding("tf-network", SourceType.TERRAFORM, {
            "rule_id": "security-group-public-admin-ingress",
            "configured_values": {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "public_cidrs": ["::/0"]},
        })
        self.assertEqual(correlate_findings([
            ("i", [iam_finding]), ("c", [cloudtrail_finding]),
            ("t", [terraform_finding, conflict]),
        ]), ())


if __name__ == "__main__":
    unittest.main()
