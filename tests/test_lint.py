import json
from pathlib import Path
import tempfile
import unittest

from ruleguard import lint
from ruleguard.cli import main
from ruleguard.core import GuardError, compare

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def rules(*bodies):
    return "<group name='t,'>" + "".join(bodies) + "</group>"


def rule(inner, rid="100300", level="5", desc=True):
    d = "<description>d</description>" if desc else ""
    return f"<rule id='{rid}' level='{level}'><if_sid>60000</if_sid>{inner}{d}</rule>"


def codes(text):
    return [f["code"] for f in lint.lint_text(text)]


class PatternChecks(unittest.TestCase):
    def test_clean_example_has_no_findings(self):
        self.assertEqual(lint.lint_paths([str(EXAMPLES / "local_rules.xml")]), [])

    def test_character_class_needs_pcre2(self):
        self.assertIn("pcre-syntax-without-type", codes(rules(rule("<regex>for [a-z]+ from</regex>"))))
        self.assertNotIn("pcre-syntax-without-type", codes(rules(rule("<regex type='pcre2'>for [a-z]+ from</regex>"))))

    def test_other_pcre_only_syntax(self):
        for pattern in ("(?i)abc", "a{3}", r"\bword", "a*?b"):
            with self.subTest(pattern=pattern):
                self.assertIn("pcre-syntax-without-type", codes(rules(rule(f"<regex>{pattern}</regex>"))))

    def test_backslash_expressions_and_plus_after_them_are_fine_in_regex(self):
        self.assertEqual([c for c in codes(rules(rule(r"<regex>^user \d+ from \S+</regex>"))) if c != "sibling-rules"], [])
        self.assertEqual(codes(rules(rule(r"<regex>port \w+</regex>"))), [])

    def test_star_after_plain_character_is_flagged(self):
        self.assertIn("bare-quantifier", codes(rules(rule("<regex>^error.*timeout</regex>"))))

    def test_backslash_in_match_is_flagged(self):
        self.assertIn("backslash-in-match", codes(rules(rule(r"<match>user \d+ locked</match>"))))
        self.assertNotIn("backslash-in-match", codes(rules(rule("<match>plain words</match>"))))


class StructureChecks(unittest.TestCase):
    def test_unknown_element_warns_and_known_ones_do_not(self):
        self.assertIn("unknown-element", codes(rules(rule("<made_up>x</made_up>"))))
        self.assertNotIn("unknown-element", codes(rules(rule("<same_srcip /><different_user /><mitre><id>T1110</id></mitre>"))))

    def test_pinned_identifiers_are_notes_not_failures(self):
        found = lint.lint_text(rules(rule("<srcip>192.0.2.9</srcip>")))
        pinned = [f for f in found if f["code"] == "pinned-identifier"]
        self.assertEqual([f["severity"] for f in pinned], ["info"])

    def test_bad_level_missing_description_and_duplicate_id(self):
        found = lint.lint_text(rules(rule("<match>a</match>", level="99", desc=False), rule("<match>b</match>")), "f.xml")
        self.assertIn("bad-level", [f["code"] for f in found])
        self.assertIn("no-description", [f["code"] for f in found])
        dup = lint.lint_text(rules(rule("<match>a</match>"), rule("<match>b</match>")))
        self.assertIn("duplicate-id", [f["code"] for f in dup])

    def test_siblings_noted_only_for_a_parent_in_the_same_files(self):
        parent = "<rule id='100400' level='3'><if_sid>60000</if_sid><match>p</match><description>d</description></rule>"
        kid = lambda rid: f"<rule id='{rid}' level='3'><if_sid>100400</if_sid><match>k</match><description>d</description></rule>"
        self.assertIn("sibling-rules", codes(rules(parent, kid("100401"), kid("100402"))))
        self.assertNotIn("sibling-rules", codes(rules(kid("100401"), kid("100402"))))

    def test_duplicate_ids_across_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("a.xml", "b.xml"):
                (Path(tmp) / name).write_text(rules(rule("<match>x</match>")), encoding="utf-8")
            self.assertIn("duplicate-id", [f["code"] for f in lint.lint_paths([tmp])])

    def test_unparsable_xml_is_an_input_error(self):
        with self.assertRaises(GuardError):
            lint.lint_text("<rule id='1'")

    def test_every_problem_in_the_demo_file_is_found(self):
        found = {f["code"] for f in lint.lint_paths([str(EXAMPLES / "rules-with-problems.xml")])}
        self.assertTrue({"pcre-syntax-without-type", "bare-quantifier", "backslash-in-match", "unknown-element",
                         "pinned-identifier", "bad-level", "no-description", "duplicate-id", "sibling-rules"} <= found)


class CliTests(unittest.TestCase):
    def test_exit_codes_and_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            warn_only = Path(tmp) / "w.xml"
            warn_only.write_text(rules(rule("<match>user \\d+</match>")), encoding="utf-8")
            self.assertEqual(main(["lint", str(warn_only)]), 0)
            self.assertEqual(main(["lint", str(warn_only), "--strict"]), 1)
            self.assertEqual(main(["lint", str(EXAMPLES / "rules-with-problems.xml")]), 1)
            self.assertEqual(main(["lint", str(EXAMPLES / "local_rules.xml")]), 0)

    def test_json_and_markdown_outputs_and_no_overwrite_of_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_json, out_md = Path(tmp) / "l.json", Path(tmp) / "l.md"
            main(["lint", str(EXAMPLES / "rules-with-problems.xml"), "--json", str(out_json), "--markdown", str(out_md)])
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["error"], 2)
            self.assertIn("pcre-syntax-without-type", out_md.read_text(encoding="utf-8"))
            src = Path(tmp) / "r.xml"
            src.write_text((EXAMPLES / "local_rules.xml").read_text(encoding="utf-8"), encoding="utf-8")
            before = src.read_text(encoding="utf-8")
            self.assertEqual(main(["lint", str(src), "--json", str(src)]), 2)
            self.assertEqual(src.read_text(encoding="utf-8"), before)

    def test_missing_path_and_empty_folder(self):
        self.assertEqual(main(["lint", "definitely-not-here.xml"]), 2)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main(["lint", tmp]), 2)


def result(case, rule_id, status="pass"):
    return {"case_id": case, "step": 1, "fingerprint": "f", "expected": {"rule_id": rule_id}, "status": status,
            "failures": [], "actual": {"rule_id": rule_id, "level": 5, "alert": True, "decoder": "d", "groups": [], "mitre": [], "warning_count": 0}}


class CompareCounts(unittest.TestCase):
    def report(self, *rows, label=None):
        r = {"schema_version": 1, "mode": "m", "results": list(rows), "passed": len(rows), "failed": 0}
        if label:
            r["label"] = label
        return r

    def test_a_rule_that_stops_matching_is_called_out(self):
        before = self.report(result("a", "100100"), result("b", "100101"), label="4.9.0")
        after = self.report(result("a", "100100"), result("b", "5710"), label="4.10.0")
        diff = compare(before, after)
        self.assertEqual(diff["dropped_to_zero"], ["100101"])
        self.assertEqual(diff["before_label"], "4.9.0")
        self.assertEqual(diff["after_label"], "4.10.0")
        self.assertIn({"rule_id": "5710", "before": 0, "after": 1}, diff["rule_counts"])

    def test_identical_runs_have_no_count_changes(self):
        rows = [result("a", "100100")]
        diff = compare(self.report(*rows), self.report(*rows))
        self.assertEqual(diff["rule_counts"], [])
        self.assertEqual(diff["dropped_to_zero"], [])

    def test_label_flag_is_saved_cleaned_and_shown(self):
        from ruleguard import report as views
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            main(["run", str(EXAMPLES / "suite.json"), "--replay", str(EXAMPLES / "synthetic-before.json"),
                  "--json", str(t / "r.json"), "--label", "wazuh 4.9.0\x1b[31m"])
            saved = json.loads((t / "r.json").read_text(encoding="utf-8"))
            self.assertTrue(saved["label"].startswith("wazuh 4.9.0"))
            self.assertNotIn("\x1b", saved["label"])
            self.assertIn("wazuh 4.9.0", views.run_html(saved))

    def test_compare_report_mentions_missing_labels_and_dropped_rules(self):
        from ruleguard import report as views
        diff = compare(self.report(result("a", "100101")), self.report(result("a", "5710")))
        html = views.compare_html(diff)
        self.assertIn("Neither run has a label", html)
        self.assertIn("matched nothing in the second run", html)
        self.assertIn("matched nothing", views.compare_markdown(diff))


if __name__ == "__main__":
    unittest.main()
