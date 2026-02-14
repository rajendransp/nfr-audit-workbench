import json
import tempfile
import unittest
from pathlib import Path

import nfr_scan


class RuleHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rules = json.loads(Path("rules/dotnet_rules.json").read_text(encoding="utf-8"))
        cls.rule_map = {r["id"]: r for r in rules}
        cls.cases = json.loads(Path("tests/rule_harness_cases.json").read_text(encoding="utf-8"))

    def test_rule_cases(self):
        for case in self.cases:
            with self.subTest(case=case["name"]):
                rule = dict(self.rule_map[case["rule_id"]])
                with tempfile.TemporaryDirectory() as tmp:
                    file_path = Path(tmp) / case["file"]
                    file_path.write_text(case["content"], encoding="utf-8")
                    matches = nfr_scan._run_regex_fallback(tmp, rule, [])
                    lines = sorted({int(m["line"]) for m in matches})
                    self.assertEqual(lines, sorted(case["expected_match_lines"]))


if __name__ == "__main__":
    unittest.main()
