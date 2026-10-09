import json
from pathlib import Path
import tempfile
import unittest

from ruleguard import coverage as cov
from ruleguard.cli import main
from ruleguard.core import GuardError, load_suite

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def suite(*cases):
    return {"schema_version": 1, "cases": [
        {"id": cid, "events": [{"event": "x", "expect": exp} for exp in exps]} for cid, exps in cases]}


class CoverageTests(unittest.TestCase):
    def test_lists_asserted_techniques_and_untagged_cases(self):
        s = suite(("a", [{"rule_id": "1", "mitre_contains": ["T1110"]}]),
                  ("b", [{"rule_id": "2", "mitre_contains": ["T1110", "T1558.003"]}]),
                  ("c", [{"alert": False}]))
        r = cov.coverage(s)
        self.assertEqual([t["technique"] for t in r["techniques"]], ["T1110", "T1558.003"])
        self.assertEqual(r["techniques"][0]["cases"], ["a", "b"])
        self.assertEqual(r["cases_without_technique"], ["c"])
        self.assertEqual(r["rules_asserted"], ["1", "2"])

    def test_wanted_parent_is_covered_by_a_sub_technique_but_not_the_reverse(self):
        s = suite(("a", [{"mitre_contains": ["T1558.003"]}]), ("b", [{"mitre_contains": ["T1110"]}]))
        self.assertEqual(cov.coverage(s, ["T1558"])["wanted_missing"], [])
        self.assertEqual(cov.coverage(s, ["T1558.004"])["wanted_missing"], ["T1558.004"])
        self.assertEqual(cov.coverage(s, ["T1110.001"])["wanted_missing"], ["T1110.001"])

    def test_wanted_ids_are_validated_normalised_and_deduplicated(self):
        self.assertEqual(cov.parse_wanted(["t1110, T1558.003", "T1110"]), ["T1110", "T1558.003"])
        for bad in ("banana", "T11", "T1110.1", "T1110;rm"):
            with self.assertRaises(GuardError):
                cov.parse_wanted([bad])

    def test_example_suite(self):
        r = cov.coverage(load_suite(EXAMPLES / "suite.json"))
        self.assertEqual([t["technique"] for t in r["techniques"]], ["T1110"])

    def test_text_and_markdown_reports(self):
        r = cov.coverage(load_suite(EXAMPLES / "suite.json"), ["T1110", "T1003"])
        text, md = cov.text_report(r), cov.markdown(r)
        self.assertIn("Wanted but not tested: T1003", text)
        self.assertIn("`T1003`", md)

    def test_hostile_case_ids_are_pipe_safe_enough_in_text(self):
        r = cov.coverage(suite(("a|b", [{"mitre_contains": ["T1110"]}])))
        self.assertIn("a|b", cov.text_report(r))


class CliTests(unittest.TestCase):
    def test_exit_code_follows_wanted_techniques(self):
        s = str(EXAMPLES / "suite.json")
        self.assertEqual(main(["coverage", s]), 0)
        self.assertEqual(main(["coverage", s, "--want", "T1110"]), 0)
        self.assertEqual(main(["coverage", s, "--want", "T1110,T1558.003"]), 1)
        self.assertEqual(main(["coverage", s, "--want", "nonsense"]), 2)

    def test_outputs_and_no_overwrite_of_the_suite(self):
        with tempfile.TemporaryDirectory() as tmp:
            j, m = Path(tmp) / "c.json", Path(tmp) / "c.md"
            main(["coverage", str(EXAMPLES / "suite.json"), "--want", "T1110", "--json", str(j), "--markdown", str(m)])
            self.assertEqual(json.loads(j.read_text(encoding="utf-8"))["techniques"][0]["technique"], "T1110")
            self.assertIn("T1110", m.read_text(encoding="utf-8"))
            src = Path(tmp) / "s.json"
            src.write_text((EXAMPLES / "suite.json").read_text(encoding="utf-8"), encoding="utf-8")
            before = src.read_text(encoding="utf-8")
            self.assertEqual(main(["coverage", str(src), "--json", str(src)]), 2)
            self.assertEqual(src.read_text(encoding="utf-8"), before)


if __name__ == "__main__":
    unittest.main()
