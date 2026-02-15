import json
import tempfile
import unittest
from pathlib import Path

import nfr_scan


class RuleHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rules = []
        for path in ("rules/dotnet_rules.json", "rules/frontend_rules.json", "rules/rest_api_rules.json", "rules/razor_rules.json"):
            rules.extend(json.loads(Path(path).read_text(encoding="utf-8-sig")))
        cls.rule_map = {r["id"]: r for r in rules}
        cls.cases = []
        for path in ("tests/rule_harness_cases.json", "tests/rule_harness_cases_fe_api.json"):
            cls.cases.extend(json.loads(Path(path).read_text(encoding="utf-8")))

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
