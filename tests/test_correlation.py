import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.correlation import correlate_findings
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


if __name__ == "__main__":
    unittest.main()
