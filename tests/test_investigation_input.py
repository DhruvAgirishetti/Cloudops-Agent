import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.correlation import Correlation, EvidenceValue, FindingRef
from cloudops_agent.investigation_input import (
    build_investigation_input,
    resolve_citation,
)
from cloudops_agent.models import Finding, Severity, SourceType


def make_finding(finding_id, source, evidence, *, title="Finding", description="Analyzer description"):
    return Finding(
        finding_id=finding_id,
        title=title,
        source_type=source,
        severity=Severity.HIGH,
        description=description,
        evidence=evidence,
        remediation="Review the configuration through the approved process.",
    )


def iam_finding(finding_id="internal-iam-id"):
    return make_finding(finding_id, SourceType.IAM, {
        "rule_id": "sensitive-iam-actions",
        "statement_index": 2,
        "Effect": "Allow",
        "Action": ["iam:CreateAccessKey"],
        "Resource": ["arn:aws:iam::123456789012:user/alice"],
        "Sid": "PrivilegedUserName",
        "Condition": {"StringEquals": {"aws:username": "alice"}},
        "matched_actions": ["iam:CreateAccessKey"],
    })


def cloudtrail_finding(finding_id="internal-cloudtrail-id"):
    return make_finding(finding_id, SourceType.CLOUDTRAIL, {
        "rule_id": "iam-create-access-key",
        "eventID": "private-event-id",
        "event": {
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "eventTime": "2026-01-01T00:00:00Z",
            "userIdentity": {"userName": "alice"},
            "sourceIPAddress": "203.0.113.44",
            "requestParameters": {"userName": "alice"},
            "responseElements": {"secretAccessKey": "must-not-pass"},
        },
    })


def terraform_finding(finding_id="internal-terraform-id"):
    return make_finding(
        finding_id,
        SourceType.TERRAFORM,
        {
            "rule_id": "security-group-public-admin-ingress",
            "filename": "customer-prod-network.tf",
            "resource_address": "aws_security_group.customer_prod.ingress[1]",
            "configured_values": {
                "protocol": "tcp",
                "public_cidrs": ["0.0.0.0/0"],
                "from_port": 22,
                "to_port": 22,
                "description": "not allowlisted",
            },
        },
        description=(
            "The aws_security_group.customer_prod.ingress[1] rule has public access. "
            "This does not establish reachability."
        ),
    )


class InvestigationInputTests(unittest.TestCase):
    def test_iam_allowlist_excludes_condition_and_redacts_identifiers(self):
        finding = iam_finding()
        result = build_investigation_input(
            user_request="Explain this policy finding.",
            scope=FindingRef("iam-analysis-result-0-privatehash", finding.finding_id),
            artifacts=[("iam-analysis-result-0-privatehash", [finding])],
        )
        serialized = repr(result.payload)
        evidence = result.payload["findings"][0]["evidence"]
        paths = [item["path"] for item in evidence]
        self.assertNotIn("Condition", paths)
        self.assertNotIn("alice", serialized)
        self.assertNotIn("123456789012", serialized)
        self.assertNotIn("privatehash", serialized)
        resource = next(item["value"] for item in evidence if item["path"] == "Resource")
        self.assertEqual(resource, ["arn:aws:iam::[REDACTED_ACCOUNT]:user/[REDACTED_RESOURCE]"])
        self.assertNotIn(finding.finding_id, serialized)
        self.assertNotIn("remediation", result.payload["findings"][0])

        with_remediation = build_investigation_input(
            user_request="Suggest advisory next steps.",
            scope=FindingRef("iam-key", finding.finding_id),
            artifacts=[("iam-key", [finding])],
            include_remediation=True,
        )
        self.assertEqual(
            with_remediation.payload["findings"][0]["remediation"]["provenance"],
            "analyzer_advisory",
        )

    def test_cloudtrail_allowlist_excludes_full_event_and_internal_ids(self):
        finding = cloudtrail_finding()
        result = build_investigation_input(
            user_request="Explain this event finding.",
            scope=FindingRef("cloudtrail-analysis-result-1-privatehash", finding.finding_id),
            artifacts=[("cloudtrail-analysis-result-1-privatehash", [finding])],
        )
        serialized = repr(result.payload)
        evidence = result.payload["findings"][0]["evidence"]
        self.assertEqual(
            [(item["path"], item["value"], item["provenance"]) for item in evidence],
            [
                ("rule_id", "iam-create-access-key", "analyzer_evidence"),
                ("event.eventSource", "iam.amazonaws.com", "analyzer_evidence"),
                ("event.eventName", "CreateAccessKey", "analyzer_evidence"),
                ("errorCode_status", "absent", "application_derived"),
            ],
        )
        for excluded in (
            finding.finding_id, "private-event-id", "privatehash", "alice",
            "203.0.113.44", "secretAccessKey", "requestParameters", "eventTime",
        ):
            self.assertNotIn(excluded, serialized)

    def test_console_login_includes_only_detection_fields(self):
        finding = make_finding("ct-login", SourceType.CLOUDTRAIL, {
            "rule_id": "console-login-without-mfa",
            "event": {
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "additionalEventData": {"MFAUsed": "No", "unused": "secret"},
                "responseElements": {"ConsoleLogin": "Success", "other": "secret"},
                "errorCode": "ignored-by-this-rule",
            },
        })
        result = build_investigation_input(
            user_request="Explain this login finding.",
            scope=FindingRef("ct-key", finding.finding_id),
            artifacts=[("ct-key", [finding])],
        )
        evidence = result.payload["findings"][0]["evidence"]
        self.assertEqual(
            [(item["path"], item["value"]) for item in evidence],
            [
                ("rule_id", "console-login-without-mfa"),
                ("event.eventSource", "signin.amazonaws.com"),
                ("event.eventName", "ConsoleLogin"),
                ("event.additionalEventData.MFAUsed", "No"),
                ("event.responseElements.ConsoleLogin", "Success"),
            ],
        )
        self.assertNotIn("ignored-by-this-rule", repr(result.payload))
        self.assertNotIn("secret", repr(result.payload))

    def test_cloudtrail_trail_operations_get_explicit_absence_evidence(self):
        for rule_id, source, name in (
            ("trail-stop-logging", "cloudtrail.amazonaws.com", "StopLogging"),
            ("trail-delete", "cloudtrail.amazonaws.com", "DeleteTrail"),
        ):
            with self.subTest(rule_id=rule_id):
                finding = make_finding("ct-id", SourceType.CLOUDTRAIL, {
                    "rule_id": rule_id,
                    "event": {"eventSource": source, "eventName": name},
                })
                result = build_investigation_input(
                    user_request="Explain this event.",
                    scope=FindingRef("ct-artifact", finding.finding_id),
                    artifacts=[("ct-artifact", [finding])],
                )
                evidence = result.payload["findings"][0]["evidence"]
                self.assertEqual(evidence[-1]["path"], "errorCode_status")
                self.assertEqual(evidence[-1]["value"], "absent")

    def test_terraform_s3_rules_include_only_rule_values(self):
        cases = (
            (
                "s3-public-acl",
                {"acl": "public-read"},
                {"configured_values.acl"},
            ),
            (
                "s3-public-access-control-disabled",
                {"block_public_acls": False, "ignore_public_acls": True},
                {"configured_values.block_public_acls"},
            ),
        )
        for rule_id, configured, expected_paths in cases:
            with self.subTest(rule_id=rule_id):
                finding = make_finding("tf-id", SourceType.TERRAFORM, {
                    "rule_id": rule_id,
                    "filename": "sensitive-name.tf",
                    "resource_address": "aws_s3_bucket_acl.assets",
                    "configured_values": {**configured, "unrelated": "omit"},
                })
                result = build_investigation_input(
                    user_request="Explain this configuration.",
                    scope=FindingRef("tf-artifact", finding.finding_id),
                    artifacts=[("tf-artifact", [finding])],
                )
                evidence = result.payload["findings"][0]["evidence"]
                self.assertEqual(
                    {item["path"] for item in evidence if item["path"].startswith("configured_values")},
                    expected_paths,
                )
                self.assertNotIn("sensitive-name.tf", repr(result.payload))
                self.assertNotIn("unrelated", repr(result.payload))

    def test_terraform_allowlist_omits_filename_and_redacts_address(self):
        finding = terraform_finding()
        result = build_investigation_input(
            user_request="Explain this network finding.",
            scope=FindingRef("terraform-key", finding.finding_id),
            artifacts=[("terraform-key", [finding])],
            artifact_limitations={"terraform-key": (
                "Dynamic blocks in aws_security_group.customer_prod are not evaluated.",
            )},
        )
        serialized = repr(result.payload)
        finding_data = result.payload["findings"][0]
        evidence = finding_data["evidence"]
        self.assertNotIn("customer-prod-network.tf", serialized)
        self.assertNotIn("customer_prod", serialized)
        self.assertNotIn("not allowlisted", serialized)
        self.assertNotIn(finding.finding_id, serialized)
        self.assertIn(
            {"path": "resource_address", "value": "aws_security_group.<resource>.ingress[1]",
             "provenance": "application_derived"},
            evidence,
        )
        self.assertEqual(result.payload["artifacts"][0]["limitations"], [
            "Dynamic blocks in aws_security_group.<resource> are not evaluated.",
        ])
        self.assertEqual(
            {item["path"] for item in evidence if item["path"].startswith("configured_values")},
            {"configured_values.protocol", "configured_values.public_cidrs",
             "configured_values.from_port", "configured_values.to_port"},
        )

    def test_terraform_ingress_allowlist_accepts_case_insensitive_tcp(self):
        finding = terraform_finding()
        finding.evidence["configured_values"]["protocol"] = "TCP"
        result = build_investigation_input(
            user_request="Explain.", scope=FindingRef("tf", finding.finding_id),
            artifacts=[("tf", [finding])],
        )
        protocol = next(
            item["value"] for item in result.payload["findings"][0]["evidence"]
            if item["path"] == "configured_values.protocol"
        )
        self.assertEqual(protocol, "TCP")

    def test_selected_correlation_includes_only_two_resolved_findings(self):
        iam = iam_finding()
        trail = cloudtrail_finding()
        iam_ref = FindingRef("iam-artifact-hash", iam.finding_id)
        trail_ref = FindingRef("ct-artifact-hash", trail.finding_id)
        correlation = Correlation(
            correlation_id="internal-correlation-id",
            relationship_type="action_overlap",
            finding_refs=(iam_ref, trail_ref),
            supporting_evidence=(
                EvidenceValue("evidence.matched_actions", "iam:CreateAccessKey"),
                EvidenceValue("evidence.event.eventSource", "iam.amazonaws.com"),
                EvidenceValue("evidence.event.eventName", "CreateAccessKey"),
            ),
            explanation="Evidence overlaps on the operation type only.",
            limitations=("Does not establish shared identity or authorization.",),
        )
        result = build_investigation_input(
            user_request="Explain this correlation.",
            scope=correlation,
            artifacts=[("iam-artifact-hash", [iam]), ("ct-artifact-hash", [trail])],
            correlations=[correlation],
        )
        payload = result.payload
        self.assertEqual(len(payload["findings"]), 2)
        self.assertEqual(len(payload["correlations"]), 1)
        serialized = repr(payload)
        for internal in (
            "internal-correlation-id", "iam-artifact-hash", "ct-artifact-hash",
            iam.finding_id, trail.finding_id,
        ):
            self.assertNotIn(internal, serialized)
        correlation_record = payload["correlations"][0]
        self.assertEqual(set(correlation_record["finding_refs"]), {
            record["finding_ref"] for record in payload["findings"]
        })
        self.assertEqual(resolve_citation(result.references, correlation_record["correlation_ref"]),
                         ("correlation", correlation.correlation_id))
        for record in payload["findings"]:
            self.assertEqual(
                resolve_citation(result.references, record["finding_ref"])[0], "finding",
            )

    def test_missing_or_stale_finding_and_correlation_endpoints_are_rejected(self):
        finding = iam_finding()
        stale_ref = FindingRef("old-artifact", finding.finding_id)
        with self.assertRaisesRegex(ValueError, "not present in the current artifacts"):
            build_investigation_input(
                user_request="Explain.", scope=stale_ref,
                artifacts=[("new-artifact", [finding])],
            )

        missing_endpoint = Correlation(
            correlation_id="corr", relationship_type="action_overlap",
            finding_refs=(stale_ref, FindingRef("missing", "missing-finding")),
            supporting_evidence=(), explanation="Overlap only.", limitations=(),
        )
        with self.assertRaisesRegex(ValueError, "not in the current correlation set"):
            build_investigation_input(
                user_request="Explain.", scope=missing_endpoint,
                artifacts=[("old-artifact", [finding])], correlations=[],
            )
        with self.assertRaisesRegex(ValueError, "findings missing"):
            build_investigation_input(
                user_request="Explain.", scope=missing_endpoint,
                artifacts=[("old-artifact", [finding])], correlations=[missing_endpoint],
            )

    def test_unknown_citations_do_not_resolve(self):
        result = build_investigation_input(
            user_request="Explain.",
            scope=FindingRef("artifact", "finding"),
            artifacts=[("artifact", [iam_finding("finding")])],
        )
        self.assertIsNone(resolve_citation(result.references, "f_from_another_request"))


if __name__ == "__main__":
    unittest.main()
