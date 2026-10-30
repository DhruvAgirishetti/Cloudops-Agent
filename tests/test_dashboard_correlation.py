import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.analysis_state import current_finding_artifacts
from cloudops_agent.correlation import correlate_findings
from cloudops_agent.models import Finding, Severity, SourceType


def make_finding(finding_id, source, evidence):
    return Finding(
        finding_id=finding_id,
        title="Finding",
        source_type=source,
        severity=Severity.MEDIUM,
        description="Description",
        evidence=evidence,
        remediation="Review.",
    )


def matching_results():
    return {
        "iam-analysis-result-0-policyhash": {
            "findings": [make_finding(
                "duplicate-id", SourceType.IAM,
                {"matched_actions": ["iam:CreateAccessKey"]},
            )],
        },
        "cloudtrail-analysis-result-0-eventhash": {
            "findings": [make_finding(
                "duplicate-id", SourceType.CLOUDTRAIL,
                {"event": {"eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey"}},
            )],
        },
    }


class DashboardCorrelationIntegrationTests(unittest.TestCase):
    def test_current_matching_results_correlate(self):
        state = matching_results()
        active = {
            "iam": {"iam-analysis-result-0-policyhash"},
            "cloudtrail": {"cloudtrail-analysis-result-0-eventhash"},
        }
        artifacts = current_finding_artifacts(state, active)
        result = correlate_findings(artifacts)
        self.assertEqual(len(result), 1)
        self.assertEqual(
            {ref.artifact_id for ref in result[0].finding_refs},
            set(active["iam"] | active["cloudtrail"]),
        )

    def test_unrelated_results_do_not_correlate(self):
        state = matching_results()
        state["iam-analysis-result-0-policyhash"]["findings"][0] = make_finding(
            "duplicate-id", SourceType.IAM, {"matched_actions": ["iam:DeleteAccessKey"]},
        )
        self.assertEqual(len(correlate_findings(current_finding_artifacts(state, {
            "iam": {"iam-analysis-result-0-policyhash"},
            "cloudtrail": {"cloudtrail-analysis-result-0-eventhash"},
        }))), 0)

    def test_missing_source_result_does_not_correlate(self):
        state = matching_results()
        for active in (
            {"iam": set(), "cloudtrail": {"cloudtrail-analysis-result-0-eventhash"}},
            {"iam": {"iam-analysis-result-0-policyhash"}, "cloudtrail": set()},
        ):
            with self.subTest(active=active):
                self.assertEqual(correlate_findings(current_finding_artifacts(state, active)), ())

    def test_replaced_or_removed_upload_results_are_excluded(self):
        state = matching_results()
        # The old IAM result remains in state for this helper-level scenario,
        # but only the replacement's current result key is eligible.
        state["iam-analysis-result-0-newhash"] = {"findings": [make_finding(
            "new-id", SourceType.IAM, {"matched_actions": ["iam:DeleteAccessKey"]},
        )]}
        current = current_finding_artifacts(state, {
            "iam": {"iam-analysis-result-0-newhash"},
            "cloudtrail": {"cloudtrail-analysis-result-0-eventhash"},
        })
        self.assertEqual(correlate_findings(current), ())
        removed = current_finding_artifacts(state, {"iam": set(), "cloudtrail": set()})
        self.assertEqual(correlate_findings(removed), ())

    def test_identical_finding_ids_in_distinct_uploads_keep_distinct_artifact_ids(self):
        state = matching_results()
        state["iam-analysis-result-1-policyhash"] = {
            "findings": [make_finding(
                "duplicate-id", SourceType.IAM,
                {"matched_actions": ["iam:CreateAccessKey"]},
            )],
        }
        artifacts = current_finding_artifacts(state, {
            "iam": {"iam-analysis-result-0-policyhash", "iam-analysis-result-1-policyhash"},
            "cloudtrail": {"cloudtrail-analysis-result-0-eventhash"},
        })
        self.assertEqual(correlate_findings(artifacts), ())
        self.assertEqual(len({artifact_id for artifact_id, _ in artifacts}), 3)

    def test_errors_and_malformed_results_are_excluded(self):
        state = matching_results()
        state["iam-analysis-result-0-policyhash"] = {"error": "invalid policy"}
        self.assertEqual(correlate_findings(current_finding_artifacts(state, {
            "iam": {"iam-analysis-result-0-policyhash"},
            "cloudtrail": {"cloudtrail-analysis-result-0-eventhash"},
        })), ())


if __name__ == "__main__":
    unittest.main()
