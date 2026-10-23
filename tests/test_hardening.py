"""Adversarial input tests: hostile, malformed or oversized input must give a clear error, never a traceback or a hang."""
import io
import json
import os
from pathlib import Path
import random
import re
import sys
import tempfile
import time
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

from ruleguard import cli, core, lint
from ruleguard import coverage as cover
from ruleguard.backends import APIBackend, ReplayBackend
from ruleguard.cli import junit, main
from ruleguard.core import GuardError, compare, load_suite, normalize, run_suite
from ruleguard.report import md_cell

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def observation(rule_id="100100"):
    return {"rule_id": rule_id, "level": 5, "alert": True, "decoder": "d", "groups": [], "mitre": [], "warning_count": 0}


def report(*rows):
    return {"schema_version": 1, "mode": "m", "results": list(rows)}


def row(case_id="a", step=1, actual=None, status="pass"):
    return {"case_id": case_id, "step": step, "fingerprint": "f", "expected": {"alert": True},
            "status": status, "failures": [], "actual": observation() if actual is None else actual}


def rule_file(body):
    return f"<group name='t,'>{body}</group>"


class Quiet:
    """Silence the CLI's own stdout and stderr while a test drives it."""

    def __enter__(self):
        self.patches = [mock.patch.object(sys, "stdout", io.StringIO()), mock.patch.object(sys, "stderr", io.StringIO())]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        self.err = sys.stderr.getvalue()
        for p in self.patches:
            p.stop()


class LintCannotBeMadeToHang(unittest.TestCase):
    """Each of these took 5 to 30 seconds at 100 KB before the fix and grows with the square of the size."""

    def assert_fast(self, text, limit=2.0):
        started = time.perf_counter()
        lint.lint_text(text)
        self.assertLess(time.perf_counter() - started, limit)

    def test_long_alternation_without_closing_paren(self):
        self.assert_fast(rule_file("<rule id='1' level='3'><regex>(" + "|" * 200_000 + "</regex><description>d</description></rule>"))

    def test_long_run_of_open_brackets(self):
        self.assert_fast(rule_file("<rule id='1' level='3'><regex>" + "[" * 200_000 + "</regex><description>d</description></rule>"))

    def test_many_rule_tags_inside_a_comment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.xml"
            path.write_text(rule_file("<rule id='1' level='3'><description>d</description></rule>") + "<!-- " + "<rule " * 40_000 + " -->",
                            encoding="utf-8")
            started = time.perf_counter()
            lint.lint_paths([str(path)])
            self.assertLess(time.perf_counter() - started, 2.0)

    def test_linear_checks_flag_exactly_what_the_old_regexes_flagged(self):
        old_alternation = re.compile(r"\([^()]*\|[^()]*\)")
        old_class = re.compile(r"(?<!\\)\[[^\]]*\]")
        rng = random.Random(7)
        for _ in range(5000):
            text = "".join(rng.choice("(|)a\\[]") for _ in range(rng.randint(0, 12)))
            self.assertEqual(bool(lint.GROUP_ALTERNATION.search(text)), bool(old_alternation.search(text)), text)
            self.assertEqual(lint._has_character_class(text), bool(old_class.search(text)), text)


class LintHostileXml(unittest.TestCase):
    def test_unicode_digits_are_findings_not_crashes(self):
        # str.isdigit() accepts a superscript two, which int() rejected with a traceback.
        found = lint.lint_text(rule_file("<rule id='100300' level='\u00b2'><description>d</description></rule>"))
        self.assertEqual([f["code"] for f in found], ["bad-level"])
        found = lint.lint_text(rule_file("<rule id='\u0661\u0662' level='3'><description>d</description></rule>"))
        self.assertEqual([f["code"] for f in found], ["bad-id"])

    def test_doctype_and_entities_are_refused(self):
        for text in ("<!DOCTYPE g [<!ENTITY a 'b'>]><group/>",
                     "<!ENTITY x SYSTEM 'file:///etc/passwd'>",
                     "<?xml version='1.0'?>\n<!doctype lolz [<!ENTITY lol 'lol'><!ENTITY l2 '&lol;&lol;&lol;'>]><group>&l2;</group>"):
            with self.assertRaises(GuardError) as caught:
                lint.lint_text(text)
            self.assertIn("DOCTYPE or ENTITY", str(caught.exception))

    def test_undefined_entity_reference_is_a_parse_error_not_a_lookup(self):
        with self.assertRaises(GuardError):
            lint.lint_text(rule_file("<rule id='1' level='3'><description>&xxe;</description></rule>"))

    def test_rule_ids_in_comments_are_not_cross_file_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.xml").write_text(rule_file("<rule id='100300' level='3'><description>d</description></rule>"), encoding="utf-8")
            (Path(tmp) / "b.xml").write_text(rule_file("<!-- old: <rule id='100300' level='3'> -->"
                                                       "<rule id='100301' level='3'><description>d</description></rule>"), encoding="utf-8")
            self.assertEqual(lint.lint_paths([tmp]), [])

    def test_real_cross_file_duplicates_still_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("a.xml", "b.xml"):
                (Path(tmp) / name).write_text(rule_file("<rule id='100300' level='3'><description>d</description></rule>"), encoding="utf-8")
            self.assertEqual([f["code"] for f in lint.lint_paths([tmp])], ["duplicate-id"])

    def test_oversized_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.xml"
            path.write_text(rule_file("<!-- " + "x" * 200 + " -->"), encoding="utf-8")
            with mock.patch.object(lint, "MAX_BYTES", 100), self.assertRaises(GuardError):
                lint.lint_paths([str(path)])

    def test_byte_order_mark_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bom.xml"
            path.write_bytes(b"\xef\xbb\xbf" + rule_file("<rule id='100300' level='3'><description>d</description></rule>").encode())
            self.assertEqual(lint.lint_paths([str(path)]), [])

    def test_symlink_out_of_a_rules_folder_is_refused_but_an_explicit_path_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "secret.xml"
            outside.write_text(rule_file("<rule id='100300' level='3'><description>d</description></rule>"), encoding="utf-8")
            folder = Path(tmp) / "rules"
            folder.mkdir()
            try:
                os.symlink(outside, folder / "link.xml")
            except (OSError, NotImplementedError):
                self.skipTest("cannot create symlinks here")
            with self.assertRaises(GuardError) as caught:
                lint.lint_paths([str(folder)])
            self.assertIn("outside", str(caught.exception))
            self.assertEqual(lint.lint_paths([str(folder / "link.xml")]), [])

    def test_markdown_cells_cannot_break_out(self):
        findings = [lint._finding("error", "bad-id", "a|b`[x](http://e).xml", "1|`2`", "m\nn|o")]
        table_rows = [line for line in lint.markdown(findings).splitlines() if line.startswith("| error")]
        self.assertEqual(len(table_rows), 1)
        self.assertNotIn("`[x]", table_rows[0])
        self.assertEqual(len(re.findall(r"(?<!\\)\|", table_rows[0])), 6)


class JsonInputs(unittest.TestCase):
    def run_cli(self, *args):
        with Quiet() as q:
            code = main(list(args))
        return code, q.err

    def test_deeply_nested_json_is_an_input_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "deep.json"
            deep.write_text("[" * 200_000, encoding="utf-8")
            code, err = self.run_cli("validate", str(deep))
            self.assertEqual(code, 2)
            self.assertNotIn("Traceback", err)
            code, _ = self.run_cli("compare", str(deep), str(deep), "--json", str(Path(tmp) / "o.json"))
            self.assertEqual(code, 2)

    def test_directory_binary_and_oversized_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_cli("validate", tmp)[0], 2)
            binary = Path(tmp) / "b.json"
            binary.write_bytes(b"\xff\xfe\x00\x01garbage")
            self.assertEqual(self.run_cli("validate", str(binary))[0], 2)
            big = Path(tmp) / "big.json"
            big.write_text(json.dumps({"schema_version": 1, "pad": "x" * 500}), encoding="utf-8")
            with mock.patch.object(core, "MAX_JSON_BYTES", 100), self.assertRaises(GuardError):
                load_suite(big)

    def test_json_with_byte_order_mark_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.json"
            path.write_bytes(b"\xef\xbb\xbf" + (EXAMPLES / "suite.json").read_bytes())
            self.assertEqual(len(load_suite(path)["cases"]), 3)

    def test_wrong_types_in_a_suite(self):
        bad_suites = [[], {"schema_version": "1", "cases": []}, {"schema_version": 1, "cases": [None]},
                      {"schema_version": 1, "cases": [{"id": 5, "events": []}]},
                      {"schema_version": 1, "cases": [{"id": "a", "events": [{"event": "x", "expect": {"level": True}}]}]},
                      {"schema_version": 1, "cases": [{"id": "a", "events": [{"event": "x", "expect": {"level": 17}}]}]},
                      {"schema_version": 1, "cases": [{"id": "a", "events": [{"event": "x", "expect": {"rule_id": 5710}}]}]},
                      {"schema_version": 1, "cases": [{"id": "a", "events": [{"event": "", "expect": {"alert": True}}]}]}]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.json"
            for value in bad_suites:
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(GuardError, msg=value):
                    load_suite(path)


class HostileReports(unittest.TestCase):
    """compare and replay read reports that anyone could have edited. A bad row must be refused, not crash sort or hash."""

    def test_compare_refuses_rows_ruleguard_could_not_have_written(self):
        bad_rows = [row(case_id=["x"]), row(case_id=None), row(step="1"), row(step=True), row(step=0),
                    row(actual={**observation(), "rule_id": ["1"]}), row(actual={**observation(), "level": "5"}),
                    row(actual={**observation(), "extra": 1}), row(status="skipped")]
        for bad in bad_rows:
            with self.assertRaises(GuardError, msg=bad):
                compare(report(row()), report(bad))

    def test_compare_still_works_on_good_rows(self):
        out = compare(report(row("a"), row("b")), report(row("a"), row("b", actual=observation("9"))))
        self.assertEqual([c["kind"] for c in out["changes"]], ["behavior_changed"])

    def test_replay_refuses_a_malformed_observation(self):
        for bad in (row(actual={**observation(), "rule_id": 5}), row(actual={**observation(), "decoder": ["x"]})):
            with self.assertRaises(GuardError):
                ReplayBackend(report(bad))

    def test_normalize_refuses_non_scalar_ids_and_tolerates_a_text_level(self):
        base = {"error": 0, "data": {"alert": True, "output": {"rule": {"id": "5710", "level": "5"}, "decoder": {"name": "sshd"}}}}
        self.assertEqual(normalize(base)["level"], 5)
        for rule in ({"id": ["5710"], "level": 5}, {"id": "1", "level": [5]}, {"id": "1", "level": True}):
            value = json.loads(json.dumps(base))
            value["data"]["output"]["rule"] = rule
            with self.assertRaises(GuardError):
                normalize(value)


class ApiSettings(unittest.TestCase):
    def test_timeout_must_be_finite_and_sane(self):
        for timeout in (0, -1, float("nan"), float("inf"), 10_000, True, "15"):
            with self.assertRaises(GuardError, msg=repr(timeout)):
                APIBackend("https://localhost:55000", "jwt", timeout=timeout)
        APIBackend("https://localhost:55000", "jwt", timeout=0.5)

    def test_token_must_be_visible_ascii(self):
        for token in ("", "a b", "a\r\nX-Injected: 1", "caf\u00e9", "a\x00b", "a\tb"):
            with self.assertRaises(GuardError, msg=repr(token)):
                APIBackend("https://localhost:55000", token)

    def test_bad_ports_and_odd_origins(self):
        for url in ("https://host:99999", "https://host:abc", "https://", "ftp://host", "https://host#frag", "https://user@host"):
            with self.assertRaises(GuardError, msg=url):
                APIBackend(url, "jwt")

    def test_session_token_from_the_server_cannot_change_the_cleanup_path(self):
        api = APIBackend("https://localhost:55000", "jwt")
        sent = []
        api.request = lambda method, path, payload=None: sent.append((method, path))
        api.session = "../../security/users?x=1"
        api.close()
        self.assertEqual(sent, [("DELETE", "/logtest/sessions/..%2F..%2Fsecurity%2Fusers%3Fx%3D1")])

    def test_hostile_manager_responses_become_clear_errors(self):
        class Reply(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class Opener:
            def __init__(self, body):
                self.body = body

            def open(self, req, timeout):
                return Reply(self.body)

        api = APIBackend("https://localhost:55000", "secret-jwt")
        for body, expected in ((b"[" * 200_000, "JSON failure"), (b" " * (4 * 1024 * 1024 + 1), "exceeds 4 MiB"),
                               (b"[1,2]", "reported an error"), (b"\xff\xfe", "JSON failure")):
            api.opener = Opener(body)
            with self.assertRaises(GuardError) as caught:
                api.request("PUT", "/logtest", {"event": "x"})
            self.assertIn(expected, str(caught.exception))
            self.assertNotIn("secret-jwt", str(caught.exception))

    def test_cli_reports_bad_timeout_without_contacting_anything(self):
        with mock.patch.dict(os.environ, {"WAZUH_API_TOKEN": "jwt"}), tempfile.TemporaryDirectory() as tmp, Quiet() as q:
            code = main(["run", str(EXAMPLES / "suite.json"), "--api", "https://localhost:1", "--timeout", "inf",
                         "--json", str(Path(tmp) / "o.json")])
        self.assertEqual(code, 2)
        self.assertIn("Timeout", q.err)


class OutputSafety(unittest.TestCase):
    def test_md_cell(self):
        self.assertEqual(md_cell("a|b`c\nd\re\x07"), "a\\|b'c d e ")

    def test_coverage_markdown_escapes_case_ids(self):
        suite = {"cases": [{"id": "x|y`z", "events": [{"event": "e", "expect": {"mitre_contains": ["T1110"]}}]},
                           {"id": "p|q", "events": [{"event": "e", "expect": {"alert": True}}]}]}
        out = cover.markdown(cover.coverage(suite))
        self.assertIn("x\\|y'z", out)
        self.assertIn("p\\|q", out)

    def test_unicode_digits_are_not_technique_ids(self):
        with self.assertRaises(GuardError):
            cover.parse_wanted(["T\u0661\u0661\u0661\u0660"])
        with self.assertRaises(GuardError):
            cover.parse_wanted(["T1110x"])
        self.assertEqual(cover.parse_wanted([" t1110 \n"]), ["T1110"])

    def test_junit_stays_valid_xml_with_control_characters(self):
        rep = {"results": [{"case_id": "a\x01b\x1b[31m", "step": 1, "status": "fail", "failures": ["bad\x00thing"]}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "j.xml"
            junit(rep, path)
            ET.parse(path)  # raises if the file is not well formed

    def test_non_ascii_output_on_a_legacy_console_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.json"
            path.write_text(json.dumps({"schema_version": 1, "cases": [{"id": "\u0645\u062b\u0627\u0644", "events": [
                {"event": "e", "expect": {"mitre_contains": ["T1110"]}}]}]}), encoding="utf-8")
            raw = io.BytesIO()
            legacy = io.TextIOWrapper(raw, encoding="cp1252")
            with mock.patch.object(sys, "stdout", legacy):
                code = main(["coverage", str(path)])
                legacy.flush()
            self.assertEqual(code, 0)
            self.assertIn(b"\\u0645", raw.getvalue())

    def test_unexpected_errors_do_not_print_a_traceback(self):
        with mock.patch.object(cli, "load_suite", side_effect=TypeError("C:\\secret\\path")), Quiet() as q:
            code = main(["validate", "x.json"])
        self.assertEqual(code, 2)
        self.assertIn("internal error (TypeError)", q.err)
        self.assertNotIn("secret", q.err)
        with mock.patch.object(cli, "load_suite", side_effect=TypeError("boom")), \
                mock.patch.dict(os.environ, {"RULEGUARD_DEBUG": "1"}), self.assertRaises(TypeError):
            main(["validate", "x.json"])


class QuickStartAndScale(unittest.TestCase):
    def test_readme_quick_start_passes(self):
        """ruleguard init, validate, then replay the shipped fixture: the README promises this works."""
        with tempfile.TemporaryDirectory() as tmp, Quiet():
            suite = Path(tmp) / "suite.json"
            self.assertEqual(main(["init", str(suite)]), 0)
            self.assertEqual(main(["validate", str(suite)]), 0)
            out = Path(tmp) / "result.json"
            code = main(["run", str(suite), "--replay", str(EXAMPLES / "synthetic-before.json"),
                         "--json", str(out), "--html", str(Path(tmp) / "result.html")])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["passed"], 2)

    def test_long_cases_and_many_cases_stay_linear(self):
        class Fake:
            mode = "fake"

            def start(self, case):
                pass

            def process(self, event):
                return observation()

            def close(self):
                pass

        long_case = {"cases": [{"id": "big", "events": [{"event": f"event {i}", "expect": {"alert": True}} for i in range(4000)]}]}
        many = {"cases": [{"id": f"c{i}", "events": [{"event": f"e{i}", "expect": {"alert": True}}]} for i in range(8000)]}
        for suite in (long_case, many):
            started = time.perf_counter()
            recorded = run_suite(suite, Fake())
            replayed = run_suite(suite, ReplayBackend(recorded))
            self.assertEqual(replayed["failed"], 0)
            self.assertLess(time.perf_counter() - started, 5.0)


if __name__ == "__main__":
    unittest.main()
