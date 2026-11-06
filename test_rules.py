import unittest

from droidweb_audit import Finding, summarize_risk, STRING_RULES


class RuleTests(unittest.TestCase):
    def test_string_rules_have_unique_ids(self):
        rule_ids = [rule[0] for rule in STRING_RULES]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))

    def test_risk_summary_counts_levels(self):
        findings = [
            Finding("1", "R1", "Example high", "test", "HIGH", "MEDIUM",
                    "TEST", {}, "reason", "validate"),
            Finding("2", "R2", "Example info", "test", "INFO", "LOW",
                    "TEST", {}, "reason", "validate"),
            Finding("3", "R3", "Example medium", "test", "MEDIUM", "LOW",
                    "TEST", {}, "reason", "validate"),
        ]
        summary = summarize_risk(findings)
        self.assertEqual(summary["highest_indicator"], "HIGH")
        self.assertEqual(summary["counts"]["HIGH"], 1)
        self.assertEqual(summary["counts"]["MEDIUM"], 1)
        self.assertEqual(summary["counts"]["INFO"], 1)
        self.assertEqual(summary["total_indicators"], 3)

    def test_empty_summary(self):
        summary = summarize_risk([])
        self.assertEqual(summary["highest_indicator"], "NONE")
        self.assertEqual(summary["total_indicators"], 0)


if __name__ == "__main__":
    unittest.main()
