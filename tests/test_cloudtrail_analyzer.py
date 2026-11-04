import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.cloudtrail_analyzer import (
    CloudTrailValidationError,
    analyze_cloudtrail_events,
)
from cloudops_agent.models import Severity, SourceType


def event(event_source, event_name, **values):
    result = {
        "eventVersion": "1.08",
        "eventTime": "2026-10-28T14:30:00Z",
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "eventID": "event-123",
        "userIdentity": {"type": "IAMUser", "userName": "demo-user"},
    }
    result.update(values)
    return result


class CloudTrailAnalyzerTests(unittest.TestCase):
    @staticmethod
    def ingress_event(**values):
        request = {"ipPermissions": {"items": [{
            "ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
        }]}}
        request.update(values.pop("requestParameters", {}))
        return event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", requestParameters=request, **values)

    def test_public_ssh_ingress_event_is_reported_with_normalized_evidence(self):
        finding = analyze_cloudtrail_events(self.ingress_event())[0]
        self.assertEqual(finding.evidence["rule_id"], "ec2-authorize-security-group-ingress-public-admin")
        self.assertEqual(finding.evidence["event"]["requestParameters"]["ipPermissions"]["items"][0]["fromPort"], 22)
        self.assertEqual(finding.evidence["matched_permissions"], [{
            "protocol": "tcp", "from_port": 22, "to_port": 22,
            "admin_ports": [22], "public_cidrs": ["0.0.0.0/0"],
        }])
        self.assertIn("does not establish", finding.description)

    def test_public_rdp_and_ipv6_ingress_are_reported(self):
        rdp = self.ingress_event(requestParameters={"ipPermissions": {"items": [{
            "ipProtocol": "6", "fromPort": 3300, "toPort": 3400,
            "ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]},
        }]}})
        finding = analyze_cloudtrail_events(rdp)[0]
        self.assertEqual(finding.evidence["matched_permissions"][0]["admin_ports"], [3389])
        self.assertEqual(finding.evidence["matched_permissions"][0]["public_cidrs"], ["::/0"])

    def test_failed_restricted_unrelated_and_malformed_ingress_do_not_match(self):
        restricted = self.ingress_event(requestParameters={"ipPermissions": {"items": [{
            "ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
            "ipRanges": {"items": [{"cidrIp": "203.0.113.0/24"}]},
        }]}})
        other_port = self.ingress_event(requestParameters={"ipPermissions": {"items": [{
            "ipProtocol": "tcp", "fromPort": 443, "toPort": 443,
            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
        }]}})
        malformed = self.ingress_event(requestParameters={"ipPermissions": "unknown"})
        for record in (
            self.ingress_event(errorCode="UnauthorizedOperation"),
            restricted, other_port, malformed,
            event("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress"),
        ):
            with self.subTest(record=record):
                self.assertEqual(analyze_cloudtrail_events(record), [])

    def test_stop_logging_event_reports_high_severity_and_preserves_evidence(self):
        record = event(
            "cloudtrail.amazonaws.com", "StopLogging", requestParameters={"name": "audit"}
        )
        finding = analyze_cloudtrail_events(record)[0]
        self.assertIs(finding.source_type, SourceType.CLOUDTRAIL)
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertEqual(finding.evidence["eventID"], "event-123")
        self.assertEqual(finding.evidence["event"]["requestParameters"], {"name": "audit"})
        self.assertIn("appears successful", finding.description)
        self.assertIn("does not confirm", finding.description)

    def test_delete_trail_event_reports_high_severity_without_claiming_certainty(self):
        finding = analyze_cloudtrail_events(
            event("cloudtrail.amazonaws.com", "DeleteTrail")
        )[0]
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertIn("appears successful", finding.description)
        self.assertIn("does not confirm", finding.description)
        self.assertNotIn("compromise occurred", finding.description)

    def test_access_key_creation_is_an_activity_indicator(self):
        finding = analyze_cloudtrail_events(
            event("iam.amazonaws.com", "CreateAccessKey", requestParameters={"userName": "demo-user"})
        )[0]
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertEqual(finding.evidence["event"]["eventName"], "CreateAccessKey")
        self.assertIn("not proof of malicious behavior", finding.description)

    def test_console_login_requires_explicit_mfa_no_and_success(self):
        record = event(
            "signin.amazonaws.com",
            "ConsoleLogin",
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
        finding = analyze_cloudtrail_events(record)[0]
        self.assertIs(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.evidence["event"]["additionalEventData"]["MFAUsed"], "No")
        self.assertEqual(finding.evidence["event"]["responseElements"]["ConsoleLogin"], "Success")

    def test_failed_cloudtrail_api_operation_does_not_match(self):
        for source, name in (
            ("cloudtrail.amazonaws.com", "StopLogging"),
            ("cloudtrail.amazonaws.com", "DeleteTrail"),
            ("iam.amazonaws.com", "CreateAccessKey"),
        ):
            with self.subTest(event=name):
                self.assertEqual(analyze_cloudtrail_events(event(source, name, errorCode="AccessDenied")), [])

    def test_unrelated_events_and_sources_do_not_match(self):
        cases = (
            event("ec2.amazonaws.com", "StopLogging"),
            event("iam.amazonaws.com", "DeleteAccessKey"),
            event("signin.amazonaws.com", "ConsoleLogin", additionalEventData={"MFAUsed": "Yes"}, responseElements={"ConsoleLogin": "Success"}),
        )
        for record in cases:
            with self.subTest(record=record):
                self.assertEqual(analyze_cloudtrail_events(record), [])

    def test_console_login_requires_all_exact_fields_and_success(self):
        base = event("signin.amazonaws.com", "ConsoleLogin")
        cases = (
            base,
            {**base, "additionalEventData": {"MFAUsed": "Yes"}, "responseElements": {"ConsoleLogin": "Success"}},
            {**base, "additionalEventData": {"MFAUsed": "No"}, "responseElements": {"ConsoleLogin": "Failure"}},
            {**base, "additionalEventData": {"MFAUsed": "No"}},
        )
        for record in cases:
            with self.subTest(record=record):
                self.assertEqual(analyze_cloudtrail_events(record), [])

    def test_records_envelope_and_multiple_events_are_supported(self):
        records = [
            event("iam.amazonaws.com", "CreateAccessKey", eventID="key-event"),
            event("cloudtrail.amazonaws.com", "StopLogging", eventID="trail-event"),
        ]
        findings = analyze_cloudtrail_events({"Records": records})
        self.assertEqual(len(findings), 2)
        self.assertEqual([finding.evidence["eventID"] for finding in findings], ["key-event", "trail-event"])

    def test_finding_ids_are_stable_and_include_rule_and_event_id(self):
        record = event("iam.amazonaws.com", "CreateAccessKey", eventID="key-event")
        first = analyze_cloudtrail_events(record)[0]
        second = analyze_cloudtrail_events(dict(record))[0]
        self.assertEqual(first.finding_id, second.finding_id)
        self.assertEqual(first.finding_id, "cloudtrail.iam-create-access-key:key-event")

    def test_fallback_finding_id_uses_stable_content_hash(self):
        record = event("iam.amazonaws.com", "CreateAccessKey")
        record.pop("eventID")
        reordered = dict(reversed(list(record.items())))
        first = analyze_cloudtrail_events(record)[0]
        second = analyze_cloudtrail_events(reordered)[0]
        self.assertEqual(first.finding_id, second.finding_id)
        self.assertIn("sha256-", first.finding_id)

    def test_identical_duplicate_event_ids_emit_one_finding(self):
        record = event("iam.amazonaws.com", "CreateAccessKey")
        findings = analyze_cloudtrail_events({"Records": [record, dict(record)]})
        self.assertEqual(len(findings), 1)

    def test_conflicting_duplicate_event_ids_reject_entire_input(self):
        first = event("iam.amazonaws.com", "CreateAccessKey", eventID="duplicate")
        conflicting = event("cloudtrail.amazonaws.com", "StopLogging", eventID="duplicate")
        with self.assertRaisesRegex(CloudTrailValidationError, "conflicting contents"):
            analyze_cloudtrail_events({"Records": [first, conflicting]})

    def test_malformed_root_envelope_and_records_are_rejected(self):
        malformed_inputs = (
            None,
            [],
            {"Records": "not a list"},
            {"Records": [event("iam.amazonaws.com", "CreateAccessKey"), "bad record"]},
            {"eventSource": "iam.amazonaws.com"},
            event("iam.amazonaws.com", "CreateAccessKey", eventID=""),
        )
        for document in malformed_inputs:
            with self.subTest(document=document):
                with self.assertRaises(CloudTrailValidationError):
                    analyze_cloudtrail_events(document)

    def test_non_string_nested_keys_and_non_json_values_are_rejected(self):
        record = event("iam.amazonaws.com", "CreateAccessKey", requestParameters={1: "bad"})
        with self.assertRaisesRegex(CloudTrailValidationError, "non-string object key"):
            analyze_cloudtrail_events(record)
        record = event("iam.amazonaws.com", "CreateAccessKey", unusual=object())
        with self.assertRaisesRegex(CloudTrailValidationError, "not valid JSON data"):
            analyze_cloudtrail_events(record)


if __name__ == "__main__":
    unittest.main()
