import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.models import Finding, Severity, SourceType


def valid_finding_values():
    return {
        "finding_id": "iam.policy.wildcard-action:example-role",
        "title": "Policy grants broad actions",
        "source_type": SourceType.IAM,
        "severity": Severity.HIGH,
        "description": "The policy permits actions beyond the intended task.",
        "evidence": {"policy": {"Statement": [{"Action": "*"}]}},
        "remediation": "Limit the allowed actions to those required by the workload.",
    }


class FindingModelTests(unittest.TestCase):
    def test_valid_finding_construction(self):
        finding = Finding(**valid_finding_values())
        self.assertEqual(finding.finding_id, "iam.policy.wildcard-action:example-role")
        self.assertIs(finding.source_type, SourceType.IAM)
        self.assertIs(finding.severity, Severity.HIGH)

    def test_valid_string_enum_values_are_normalized(self):
        values = valid_finding_values()
        values["source_type"] = "CloudTrail"
        values["severity"] = "Informational"
        finding = Finding(**values)
        self.assertIs(finding.source_type, SourceType.CLOUDTRAIL)
        self.assertIs(finding.severity, Severity.INFORMATIONAL)

    def test_invalid_source_value_has_clear_error(self):
        values = valid_finding_values()
        values["source_type"] = "Azure"
        with self.assertRaisesRegex(ValueError, "source_type must be one of: CloudTrail, IAM, Terraform"):
            Finding(**values)

    def test_invalid_severity_value_has_clear_error(self):
        values = valid_finding_values()
        values["severity"] = "Urgent"
        with self.assertRaisesRegex(ValueError, "severity must be one of: Critical, High, Medium, Low, Informational"):
            Finding(**values)

    def test_blank_required_text_fields_are_rejected(self):
        for field_name in ("finding_id", "title", "description", "remediation"):
            with self.subTest(field=field_name):
                values = valid_finding_values()
                values[field_name] = " \t\n "
                with self.assertRaisesRegex(ValueError, f"{field_name} must not be empty or whitespace-only"):
                    Finding(**values)

    def test_omitted_required_fields_raise_clear_type_error(self):
        required_fields = (
            "finding_id",
            "title",
            "source_type",
            "severity",
            "description",
            "evidence",
            "remediation",
        )
        for field_name in required_fields:
            with self.subTest(field=field_name):
                values = valid_finding_values()
                del values[field_name]
                with self.assertRaisesRegex(TypeError, field_name):
                    Finding(**values)

    def test_nested_evidence_is_copied_and_preserved(self):
        nested = {"eventName": "CreateAccessKey", "requestParameters": {"userName": "demo-user"}}
        original = MappingProxyType({"cloudtrail_record": nested})
        values = valid_finding_values()
        values["evidence"] = original

        finding = Finding(**values)

        self.assertEqual(finding.evidence, {"cloudtrail_record": nested})
        self.assertIsNot(finding.evidence["cloudtrail_record"], nested)

    def test_nested_caller_mutations_do_not_change_finding_evidence(self):
        original = {"record": {"eventName": "CreateAccessKey", "tags": ["audit"]}}
        values = valid_finding_values()
        values["evidence"] = original
        finding = Finding(**values)

        original["record"]["eventName"] = "DeleteTrail"
        original["record"]["tags"].append("changed")

        self.assertEqual(
            finding.evidence,
            {"record": {"eventName": "CreateAccessKey", "tags": ["audit"]}},
        )

    def test_finding_fields_are_immutable_after_construction(self):
        finding = Finding(**valid_finding_values())
        with self.assertRaises(FrozenInstanceError):
            finding.title = "Changed after validation"
        with self.assertRaises(FrozenInstanceError):
            finding.severity = "invalid"

    def test_non_mapping_evidence_is_rejected(self):
        values = valid_finding_values()
        values["evidence"] = ["not", "a", "mapping"]
        with self.assertRaisesRegex(TypeError, "evidence must be a mapping"):
            Finding(**values)

    def test_non_string_top_level_evidence_key_is_rejected(self):
        values = valid_finding_values()
        values["evidence"] = {7: "invalid key"}
        with self.assertRaisesRegex(TypeError, "evidence mapping keys must be strings.*7.*evidence"):
            Finding(**values)

    def test_non_string_nested_evidence_key_is_rejected(self):
        values = valid_finding_values()
        values["evidence"] = {"policy": {"Statement": [{3: "invalid key"}]}}
        with self.assertRaisesRegex(TypeError, "evidence mapping keys must be strings.*3.*evidence.policy.Statement"):
            Finding(**values)

    def test_empty_evidence_mapping_is_allowed(self):
        values = valid_finding_values()
        values["evidence"] = {}
        finding = Finding(**values)
        self.assertEqual(finding.evidence, {})


if __name__ == "__main__":
    unittest.main()
