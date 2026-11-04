import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudops_agent.iam_analyzer import IAMPolicyValidationError, analyze_iam_policy
from cloudops_agent.models import Severity, SourceType


def statement(effect="Allow", action="s3:GetObject", resource="arn:aws:s3:::example-bucket/*", **extra):
    result = {"Effect": effect, "Action": action, "Resource": resource}
    result.update(extra)
    return result


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


class IAMAnalyzerTests(unittest.TestCase):
    def test_exact_security_group_ingress_action_is_retained_for_correlation(self):
        findings = analyze_iam_policy({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "ec2:AuthorizeSecurityGroupIngress",
                "Resource": "*",
            }],
        })
        sensitive = [item for item in findings if item.evidence.get("matched_actions")]
        self.assertEqual(len(sensitive), 1)
        self.assertEqual(sensitive[0].evidence["matched_actions"], ["ec2:AuthorizeSecurityGroupIngress"])

    def test_unrestricted_wildcard_allow_is_high_severity(self):
        findings = analyze_iam_policy(policy(statement(action="*", resource="*", Sid="Admin")))
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertIs(finding.source_type, SourceType.IAM)
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertIn("all-character '*' wildcard", finding.description)
        self.assertEqual(finding.evidence["statement_index"], 1)
        self.assertEqual(finding.evidence["Sid"], "Admin")
        self.assertEqual(finding.evidence["Action"], "*")
        self.assertEqual(finding.evidence["Resource"], "*")

    def test_service_wide_iam_actions_match_case_insensitively(self):
        findings = analyze_iam_policy(policy(statement(action="IAM:*", resource="*")))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["rule_id"], "service-wide-iam-actions")
        self.assertIs(findings[0].severity, Severity.HIGH)
        self.assertIn("does not establish effective access", findings[0].description)
        self.assertIn("where those actions support resource-level permissions", findings[0].remediation)

    def test_repeated_asterisks_keep_unrestricted_and_service_wide_precedence(self):
        unrestricted = analyze_iam_policy(
            policy(statement(action="**", resource="***"))
        )
        service_wide = analyze_iam_policy(
            policy(statement(action="IAM:**", resource="**"))
        )
        self.assertEqual(unrestricted[0].evidence["rule_id"], "unrestricted-wildcard-allow")
        self.assertEqual(service_wide[0].evidence["rule_id"], "service-wide-iam-actions")

    def test_sensitive_actions_are_exact_and_case_insensitive(self):
        findings = analyze_iam_policy(
            policy(
                statement(
                    action=["IAM:CREATEACCESSKEY", "iam:PutUserPolicy", "iam:AttachUserPolicy"],
                    resource=["arn:aws:iam::123456789012:user/demo"],
                )
            )
        )
        self.assertEqual(len(findings), 1)
        self.assertIs(findings[0].severity, Severity.MEDIUM)
        self.assertEqual(
            findings[0].evidence["matched_actions"],
            ["iam:CreateAccessKey", "iam:AttachUserPolicy", "iam:PutUserPolicy"],
        )
        self.assertIn("does not prove privilege escalation", findings[0].description)

    def test_action_globs_match_only_sensitive_allowlist_actions(self):
        findings = analyze_iam_policy(
            policy(statement(action="iam:Create*", resource="*"))
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].evidence["matched_actions"],
            ["iam:CreateAccessKey", "iam:CreatePolicyVersion"],
        )

    def test_access_key_glob_matches_the_matching_allowlist_action(self):
        findings = analyze_iam_policy(
            policy(statement(action="iam:*AccessKey*", resource="*"))
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["matched_actions"], ["iam:CreateAccessKey"])

    def test_question_mark_and_case_variations_match_sensitive_actions(self):
        findings = analyze_iam_policy(
            policy(statement(action="I?M:CREATEACCESSKE?", resource="*"))
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["matched_actions"], ["iam:CreateAccessKey"])

    def test_wildcard_pattern_without_sensitive_match_emits_no_finding(self):
        findings = analyze_iam_policy(policy(statement(action="iam:Delete*", resource="*")))
        self.assertEqual(findings, [])

    def test_sensitive_rule_does_not_use_substring_matching(self):
        findings = analyze_iam_policy(policy(statement(action="iam:CreateAccessKeyForTest")))
        self.assertEqual(findings, [])

    def test_string_and_list_forms_of_action_and_resource_are_supported(self):
        string_finding = analyze_iam_policy(policy(statement(action="*", resource="*")))
        list_finding = analyze_iam_policy(
            {"Statement": statement(action=["*"], resource=["*"])}
        )
        self.assertEqual(len(string_finding), 1)
        self.assertEqual(len(list_finding), 1)
        self.assertEqual(string_finding[0].evidence["Action"], "*")
        self.assertEqual(list_finding[0].evidence["Action"], ["*"])

    def test_multiple_matching_statements_have_distinct_ids_and_evidence(self):
        findings = analyze_iam_policy(
            policy(
                statement(action="*", resource="*", Sid="First"),
                statement(action="*", resource="*", Sid="Second"),
            )
        )
        self.assertEqual(len(findings), 2)
        self.assertNotEqual(findings[0].finding_id, findings[1].finding_id)
        self.assertEqual([item.evidence["statement_index"] for item in findings], [1, 2])
        self.assertEqual([item.evidence["Sid"] for item in findings], ["First", "Second"])

    def test_rule_precedence_emits_one_finding_per_statement(self):
        findings = analyze_iam_policy(
            policy(
                statement(
                    action=["*", "iam:*", "iam:CreateAccessKey"],
                    resource=["*"],
                )
            )
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["rule_id"], "unrestricted-wildcard-allow")

    def test_iam_wildcard_takes_precedence_over_sensitive_action(self):
        findings = analyze_iam_policy(
            policy(statement(action=["iam:*", "iam:CreateAccessKey"], resource="*"))
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["rule_id"], "service-wide-iam-actions")

    def test_narrow_permissions_do_not_trigger_broad_rules(self):
        findings = analyze_iam_policy(
            policy(
                statement(action="s3:Get*", resource="arn:aws:s3:::example-bucket/*"),
                statement(action="s3:GetObject", resource="*"),
                statement(action="*", resource="arn:aws:s3:::example-bucket/*"),
            )
        )
        self.assertEqual(findings, [])

    def test_deny_statements_do_not_trigger_allow_risk_findings(self):
        findings = analyze_iam_policy(policy(statement(effect="Deny", action="*", resource="*")))
        self.assertEqual(findings, [])

    def test_deny_statement_does_not_suppress_separate_allow_finding(self):
        findings = analyze_iam_policy(
            policy(
                statement(effect="Allow", action="*", resource="*"),
                statement(effect="Deny", action="*", resource="*"),
            )
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["statement_index"], 1)

    def test_condition_is_preserved_and_described_as_unevaluated(self):
        condition = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
        findings = analyze_iam_policy(
            policy(statement(action="*", resource="*", Condition=condition))
        )
        self.assertEqual(findings[0].evidence["Condition"], condition)
        self.assertIn("Condition is present", findings[0].description)
        self.assertIn("semantics were not evaluated", findings[0].description)
        self.assertIn("does not establish effective access", findings[0].description)

    def test_empty_statement_list_returns_no_findings(self):
        self.assertEqual(analyze_iam_policy({"Statement": []}), [])

    def test_unexpected_root_types_are_rejected(self):
        for document in (None, [], "{}", 42):
            with self.subTest(document=document):
                with self.assertRaisesRegex(IAMPolicyValidationError, "Policy document must be a JSON object"):
                    analyze_iam_policy(document)

    def test_missing_statement_field_is_rejected(self):
        with self.assertRaisesRegex(IAMPolicyValidationError, "missing required field 'Statement'"):
            analyze_iam_policy({"Version": "2012-10-17"})

    def test_supported_policy_versions_are_accepted_and_version_is_optional(self):
        for document in (
            {"Version": "2008-10-17", "Statement": []},
            {"Version": "2012-10-17", "Statement": []},
            {"Statement": []},
        ):
            with self.subTest(document=document):
                self.assertEqual(analyze_iam_policy(document), [])

    def test_invalid_policy_versions_are_rejected(self):
        for version in ("2020-01-01", "", None, 2012):
            with self.subTest(version=version):
                with self.assertRaisesRegex(IAMPolicyValidationError, "field 'Version' must be one of"):
                    analyze_iam_policy({"Version": version, "Statement": []})

    def test_top_level_id_and_unexpected_fields_are_rejected(self):
        for document, message in (
            ({"Id": "policy-id", "Statement": []}, "Top-level 'Id'.*not supported"),
            ({"Metadata": "extra", "Statement": []}, "unsupported top-level field 'Metadata'"),
        ):
            with self.subTest(document=document):
                with self.assertRaisesRegex(IAMPolicyValidationError, message):
                    analyze_iam_policy(document)

    def test_sid_uses_ascii_alphanumeric_grammar_and_remains_optional(self):
        valid_with_sid = policy(statement(action="s3:GetObject", Sid="ReadBucket9"))
        valid_without_sid = policy(statement(action="s3:GetObject"))
        self.assertEqual(analyze_iam_policy(valid_with_sid), [])
        self.assertEqual(analyze_iam_policy(valid_without_sid), [])

        for sid in ("", "two words", "has-hyphen", "underscore_", "éclair", 12):
            with self.subTest(sid=sid):
                with self.assertRaisesRegex(IAMPolicyValidationError, "Sid.*only ASCII letters and digits"):
                    analyze_iam_policy(policy(statement(Sid=sid)))

    def test_duplicate_sids_are_rejected(self):
        with self.assertRaisesRegex(IAMPolicyValidationError, "duplicate Sid 'Same'"):
            analyze_iam_policy(
                policy(statement(Sid="Same"), statement(Sid="Same"))
            )

    def test_malformed_statement_container_or_item_is_rejected(self):
        for document in ({"Statement": "bad"}, {"Statement": [statement(), "bad"]}):
            with self.subTest(document=document):
                with self.assertRaises(IAMPolicyValidationError):
                    analyze_iam_policy(document)

    def test_missing_required_statement_fields_are_rejected(self):
        for missing_field in ("Effect", "Action", "Resource"):
            with self.subTest(field=missing_field):
                item = statement()
                del item[missing_field]
                with self.assertRaisesRegex(IAMPolicyValidationError, f"missing required field '{missing_field}'"):
                    analyze_iam_policy(policy(item))

    def test_invalid_effect_and_malformed_action_resource_are_rejected(self):
        invalid_cases = [
            (statement(effect="allow"), "Effect"),
            (statement(action=""), "Action"),
            (statement(action=[]), "Action"),
            (statement(action=["s3:GetObject", 4]), "Action"),
            (statement(resource=""), "Resource"),
            (statement(resource=[]), "Resource"),
            (statement(resource=["arn:aws:s3:::bucket", None]), "Resource"),
        ]
        for item, field_name in invalid_cases:
            with self.subTest(item=item):
                with self.assertRaisesRegex(IAMPolicyValidationError, field_name):
                    analyze_iam_policy(policy(item))

    def test_condition_must_be_an_object(self):
        with self.assertRaisesRegex(IAMPolicyValidationError, "Condition.*must be an object"):
            analyze_iam_policy(policy(statement(Condition="not-an-object")))

    def test_non_string_condition_keys_nested_in_lists_and_tuples_are_rejected(self):
        condition = {"Bool": {"example:key": [{"nested": ({7: "invalid"},)}]}}
        with self.assertRaisesRegex(IAMPolicyValidationError, "non-string object key: 7"):
            analyze_iam_policy(
                policy(statement(action="*", resource="*", Condition=condition))
            )

    def test_unsupported_policy_elements_are_rejected_explicitly(self):
        unsupported_fields = ("NotAction", "NotResource", "Principal", "NotPrincipal")
        for field_name in unsupported_fields:
            with self.subTest(field=field_name):
                item = statement(**{field_name: "*"})
                with self.assertRaisesRegex(IAMPolicyValidationError, f"unsupported field '{field_name}'"):
                    analyze_iam_policy(policy(item))

    def test_no_partial_findings_are_returned_when_a_later_statement_is_invalid(self):
        invalid = statement()
        del invalid["Resource"]
        with self.assertRaisesRegex(IAMPolicyValidationError, "missing required field 'Resource'"):
            analyze_iam_policy(
                policy(statement(action="*", resource="*"), invalid)
            )


if __name__ == "__main__":
    unittest.main()
