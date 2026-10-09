import json
from pathlib import Path
import tempfile
import unittest

from ruleguard import report as views
from ruleguard.cli import main
from ruleguard.core import load_suite

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SCHEMA = Path(__file__).resolve().parent.parent / "ruleguard" / "suite.schema.json"


def make_report():
    return {"schema_version": 1, "mode": "offline-replay", "passed": 1, "failed": 1, "results": [
        {"case_id": "a|b", "step": 1, "status": "pass", "failures": [],
         "expected": {"rule_id": "100100"}, "actual": {"rule_id": "100100", "level": 10, "alert": True, "decoder": "json", "groups": ["g"], "mitre": [], "warning_count": 0}},
        {"case_id": "<img src=x onerror=1>", "step": 2, "status": "fail", "failures": ["rule_id: expectation not met"],
         "expected": {"rule_id": "1"}, "actual": {"rule_id": "<b>2</b>", "level": 3, "alert": False, "decoder": None, "groups": [], "mitre": [], "warning_count": 0}}]}


class ReportTests(unittest.TestCase):
    def test_run_html_shows_counts_and_escapes_everything(self):
        out = views.run_html(make_report())
        self.assertIn("passed", out)
        self.assertIn("Replay checks stored observations", out)
        for bad in ("<img src=x", "<b>2</b>"):
            self.assertNotIn(bad, out)
        self.assertIn("&lt;img src=x", out)
        self.assertNotIn("<script", out)
        self.assertIn("default-src 'none'", out)

    def test_compare_html_with_and_without_changes(self):
        empty = views.compare_html({"changes": [], "before_mode": "m", "after_mode": "m"})
        self.assertIn("No differences", empty)
        change = {"case_id": "<x>", "step": 1, "kind": "behavior_changed",
                  "before": {"rule_id": "1", "alert": False}, "after": {"rule_id": "2", "alert": True}}
        out = views.compare_html({"changes": [change], "before_mode": "m", "after_mode": "m"})
        self.assertIn("behavior_changed", out)
        self.assertNotIn("<x>", out)

    def test_markdown_escapes_table_pipes(self):
        out = views.run_markdown(make_report())
        self.assertIn(r"a\|b", out)
        self.assertEqual(out.count("\n| "), 3)

    def test_cli_writes_html_and_markdown_for_run_and_compare(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            self.assertEqual(main(["run", str(EXAMPLES / "suite.json"), "--replay", str(EXAMPLES / "synthetic-before.json"),
                                   "--json", str(t / "r.json"), "--html", str(t / "r.html"), "--markdown", str(t / "r.md")]), 0)
            self.assertIn("healthcheck-exception", (t / "r.md").read_text(encoding="utf-8"))
            self.assertEqual(main(["compare", str(EXAMPLES / "synthetic-before.json"), str(EXAMPLES / "synthetic-after.json"),
                                   "--json", str(t / "d.json"), "--html", str(t / "d.html"), "--markdown", str(t / "d.md")]), 1)
            self.assertIn("behavior_changed", (t / "d.md").read_text(encoding="utf-8"))

    def test_markdown_output_cannot_overwrite_an_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            suite = Path(tmp) / "s.json"
            suite.write_text((EXAMPLES / "suite.json").read_text(encoding="utf-8"), encoding="utf-8")
            before = suite.read_text(encoding="utf-8")
            code = main(["run", str(suite), "--replay", str(EXAMPLES / "synthetic-before.json"), "--json", str(Path(tmp) / "r.json"), "--markdown", str(suite)])
            self.assertEqual(code, 2)
            self.assertEqual(suite.read_text(encoding="utf-8"), before)


class InitAndSchemaTests(unittest.TestCase):
    def test_init_writes_a_valid_suite_and_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "suite.json"
            self.assertEqual(main(["init", str(target)]), 0)
            self.assertEqual(len(load_suite(target)["cases"]), 2)
            first = target.read_text(encoding="utf-8")
            self.assertEqual(main(["init", str(target)]), 2)
            self.assertEqual(target.read_text(encoding="utf-8"), first)

    def test_schema_is_valid_json_and_matches_the_validator_keys(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        expect_keys = set(schema["properties"]["cases"]["items"]["properties"]["events"]["items"]["properties"]["expect"]["properties"])
        from ruleguard.core import CHECKS
        self.assertEqual(expect_keys, set(CHECKS))
        event_keys = set(schema["properties"]["cases"]["items"]["properties"]["events"]["items"]["properties"])
        self.assertEqual(event_keys, {"event", "location", "log_format", "expect"})

    def test_example_suite_declares_nothing_the_schema_forbids(self):
        suite = json.loads((EXAMPLES / "suite.json").read_text(encoding="utf-8"))
        self.assertEqual(suite["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
