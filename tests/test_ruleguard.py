import copy
import json
from pathlib import Path
import tempfile
import unittest

from ruleguard.backends import APIBackend, ReplayBackend
from ruleguard.cli import main, junit, write_html
from ruleguard.core import GuardError, check, compare, fingerprint, load_suite, normalize, run_suite


def response(rule_id="5710", token="abc", warnings=None):
    return {"error": 0, "data": {"token": token, "alert": True, "messages": warnings or [],
        "output": {"rule": {"id": rule_id, "level": 5, "groups": ["sshd"],
                            "mitre": {"id": ["T1110"]}},
                   "decoder": {"name": "sshd"}, "full_log": "secret must never be reported"}}}


def suite():
    return {"schema_version": 1, "cases": [{"id": "ssh", "events": [
        {"event": "synthetic SSH event", "expect": {"rule_id": "5710", "alert": True}},
        {"event": "second SSH event", "expect": {"rule_id": "5712", "mitre_contains": ["T1110"]}}]}]}


class FakeAPI(APIBackend):
    def __init__(self, replies):
        super().__init__("https://localhost:55000", "test-jwt")
        self.replies, self.requests = list(replies), []

    def request(self, method, path, payload=None):
        self.requests.append((method, path, payload))
        if method == "DELETE":
            return {"error": 0}
        return self.replies.pop(0)


class Tests(unittest.TestCase):
    def test_normalization_omits_raw_logs_and_tokens(self):
        value = json.dumps(normalize(response()))
        self.assertNotIn("secret", value)
        self.assertNotIn("abc", value)

    def test_correlation_reuses_token_and_closes(self):
        api = FakeAPI([response(), response("5712")])
        result = run_suite(suite(), api)
        self.assertEqual(result["failed"], 0)
        self.assertNotIn("token", api.requests[0][2])
        self.assertEqual(api.requests[1][2]["token"], "abc")
        self.assertEqual(api.requests[-1][0], "DELETE")

    def test_cases_have_isolated_sessions(self):
        manifest = suite()
        manifest["cases"].append(copy.deepcopy(manifest["cases"][0]))
        manifest["cases"][1]["id"] = "other"
        api = FakeAPI([response(), response("5712"), response(), response("5712")])
        run_suite(manifest, api)
        self.assertNotIn("token", api.requests[3][2])

    def test_session_reset_is_error_not_pass(self):
        api = FakeAPI([response(), response("5712", "replacement")])
        result = run_suite(suite(), api)
        self.assertEqual(result["results"][-1]["status"], "error")
        self.assertIn("replacement", api.requests[-1][1])

    def test_warnings_fail_even_if_rule_matches(self):
        result = run_suite(suite(), FakeAPI([response(warnings=["WARNING: missing list"]), response("5712")]))
        self.assertEqual(result["failed"], 1)

    def test_negative_case_forbidden_rule(self):
        self.assertTrue(check({"forbidden_rule_ids": ["5710"]}, normalize(response())))

    def test_no_match_is_valid(self):
        actual = normalize({"error": 0, "data": {"alert": False, "output": {"decoder": {}}}})
        self.assertEqual(check({"rule_id": None, "alert": False}, actual), [])

    def test_invalid_api_envelope_is_error(self):
        for value in [{"error": 5}, {"error": 0, "data": {}}, {"error": 0, "data": {"output": {}, "alert": "false"}}]:
            with self.assertRaises(GuardError):
                normalize(value)

    def test_recording_replay_and_input_fingerprint(self):
        manifest = suite()
        recorded = run_suite(manifest, FakeAPI([response(), response("5712")]))
        result = run_suite(manifest, ReplayBackend(recorded))
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["mode"], "offline-replay")
        manifest["cases"][0]["events"][0]["event"] = "changed"
        self.assertEqual(run_suite(manifest, ReplayBackend(recorded))["failed"], 1)

    def test_compare_distinguishes_input_and_behavior_changes(self):
        old = run_suite(suite(), FakeAPI([response(), response("5712")]))
        new = copy.deepcopy(old)
        new["results"][0]["actual"]["rule_id"] = "other"
        self.assertEqual(compare(old, new)["changes"][0]["kind"], "behavior_changed")
        new["results"][0]["fingerprint"] = "different"
        self.assertEqual(compare(old, new)["changes"][0]["kind"], "input_changed")

    def test_compare_refuses_incomplete_results(self):
        report = run_suite(suite(), FakeAPI([response(), response("5712", "changed")]))
        with self.assertRaises(GuardError):
            compare(report, report)

    def test_manifest_rejects_duplicate_and_typo(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suite.json"
            manifest = suite()
            manifest["cases"].append(manifest["cases"][0])
            path.write_text(json.dumps(manifest))
            with self.assertRaises(GuardError):
                load_suite(path)
            manifest = suite()
            manifest["cases"][0]["events"][0]["expect"] = {"ruleid": "5710"}
            path.write_text(json.dumps(manifest))
            with self.assertRaises(GuardError):
                load_suite(path)

    def test_input_output_collision_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suite.json"
            content = json.dumps(suite())
            path.write_text(content)
            self.assertEqual(main(["run", str(path), "--replay", str(path), "--json", str(path)]), 2)
            self.assertEqual(path.read_text(), content)

    def test_reports_escape_untrusted_case_names(self):
        report = run_suite(suite(), FakeAPI([response(), response("5712")]))
        report["results"][0]["case_id"] = "<script>alert(1)</script>"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.html"
            write_html(report, path)
            self.assertNotIn("<script>", path.read_text())
            junit(report, Path(tmp) / "report.xml")

    def test_https_origin_only(self):
        for url in ["http://localhost:55000", "https://a:b@host", "https://host/path", "https://host?token=secret"]:
            with self.assertRaises(GuardError):
                APIBackend(url, "jwt")


if __name__ == "__main__":
    unittest.main()
