"""Manifest validation, expectations, and stable result comparison."""
import hashlib
import json


class GuardError(Exception):
    """An actionable input or backend failure, without secret-bearing payloads."""


CHECKS = {"rule_id", "forbidden_rule_ids", "level", "alert", "decoder",
          "groups_contains", "mitre_contains"}


def fingerprint(case):
    payload = [{k: event.get(k, default) for k, default in
                (("event", None), ("location", "ruleguard"), ("log_format", "syslog"))}
               for event in case["events"]]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def load_suite(path):
    try:
        suite = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GuardError("Cannot read suite JSON") from exc
    if not isinstance(suite, dict) or suite.get("schema_version") != 1:
        raise GuardError("Suite must have schema_version 1")
    cases = suite.get("cases")
    if not isinstance(cases, list) or not cases:
        raise GuardError("Suite needs a non-empty cases array")
    ids = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not case["id"].strip():
            raise GuardError("Each case needs a non-empty string id")
        if case["id"] in ids:
            raise GuardError("Duplicate case id")
        ids.add(case["id"])
        events = case.get("events")
        if not isinstance(events, list) or not events:
            raise GuardError("Each case needs a non-empty events array")
        for event in events:
            if not isinstance(event, dict) or not isinstance(event.get("event"), str) or not event["event"].strip():
                raise GuardError("Each event needs a non-empty raw event string")
            if set(event) - {"event", "location", "log_format", "expect"}:
                raise GuardError("Unknown event field; check spelling")
            for key in ("location", "log_format"):
                if key in event and (not isinstance(event[key], str) or not event[key].strip()):
                    raise GuardError("location and log_format must be non-empty strings")
            expect = event.get("expect")
            if not isinstance(expect, dict) or not expect or set(expect) - CHECKS:
                raise GuardError("Each event needs at least one supported expectation")
            for key, value in expect.items():
                if key == "alert" and not isinstance(value, bool):
                    raise GuardError("alert must be boolean")
                if key == "level" and (type(value) is not int or not 0 <= value <= 16):
                    raise GuardError("level must be an integer from 0 to 16")
                if key in {"rule_id", "decoder"} and value is not None and not isinstance(value, str):
                    raise GuardError("rule_id and decoder must be strings or null")
                if key in {"forbidden_rule_ids", "groups_contains", "mitre_contains"}:
                    if not isinstance(value, list) or not value or not all(isinstance(x, str) for x in value):
                        raise GuardError("List expectations need a non-empty string array")
    return suite


def normalize(response):
    if not isinstance(response, dict) or response.get("error") != 0:
        raise GuardError("Wazuh returned an unsuccessful logtest response")
    data = response.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("output"), dict) or type(data.get("alert")) is not bool:
        raise GuardError("Unsupported logtest response shape")
    output = data["output"]
    rule = output.get("rule", {})
    decoder = output.get("decoder", {})
    if not isinstance(rule, dict) or not isinstance(decoder, dict):
        raise GuardError("Malformed rule or decoder response")
    mitre = rule.get("mitre", {})
    if not isinstance(mitre, dict):
        raise GuardError("Malformed MITRE response")
    groups, techniques = rule.get("groups", []), mitre.get("id", [])
    if not isinstance(groups, list) or not isinstance(techniques, list):
        raise GuardError("Malformed rule metadata")
    if not all(isinstance(x, str) for x in groups + techniques):
        raise GuardError("Malformed rule metadata items")
    messages = data.get("messages", [])
    if not isinstance(messages, list) or not all(isinstance(x, str) for x in messages):
        raise GuardError("Malformed logtest messages")
    rule_id = rule.get("id")
    return {
        "rule_id": str(rule_id) if rule_id is not None else None,
        "level": rule.get("level"), "alert": data["alert"],
        "decoder": decoder.get("name"),
        "groups": sorted(set(groups)), "mitre": sorted(set(techniques)),
        "warning_count": sum("WARNING:" in m or "ERROR:" in m for m in messages),
    }


def check(expect, actual, allow_warnings=False):
    failures = []
    for key, value in expect.items():
        if key == "forbidden_rule_ids":
            if actual["rule_id"] in value:
                failures.append("forbidden rule matched")
        elif key in {"groups_contains", "mitre_contains"}:
            field = "groups" if key == "groups_contains" else "mitre"
            if not set(value).issubset(actual[field]):
                failures.append(f"{key}: expected values missing")
        elif actual.get(key) != value:
            failures.append(f"{key}: expectation not met")
    if actual["warning_count"] and not allow_warnings:
        failures.append("backend emitted warnings/errors; inspect manager locally")
    return failures


def run_suite(suite, backend, allow_warnings=False):
    rows = []
    for case in suite["cases"]:
        started = False
        try:
            backend.start(case)
            started = True
            for index, event in enumerate(case["events"]):
                actual = backend.process(event)
                failures = check(event["expect"], actual, allow_warnings)
                rows.append({"case_id": case["id"], "step": index + 1,
                             "fingerprint": fingerprint(case),
                             "expected": event["expect"], "actual": actual,
                             "status": "fail" if failures else "pass", "failures": failures})
        except GuardError as exc:
            rows.append({"case_id": case["id"], "step": None,
                         "fingerprint": fingerprint(case), "status": "error",
                         "failures": [str(exc)], "actual": None})
        finally:
            if started:
                try:
                    backend.close()
                except GuardError as exc:
                    rows.append({"case_id": case["id"], "step": None,
                                 "fingerprint": fingerprint(case), "status": "error",
                                 "failures": [str(exc)], "actual": None})
    return {"schema_version": 1, "mode": backend.mode, "results": rows,
            "passed": sum(r["status"] == "pass" for r in rows),
            "failed": sum(r["status"] != "pass" for r in rows)}


def compare(before, after):
    for report in (before, after):
        if not isinstance(report, dict) or report.get("schema_version") != 1 or not isinstance(report.get("results"), list):
            raise GuardError("Unsupported report")
    def indexed(report):
        entries = {}
        for row in report["results"]:
            if not isinstance(row, dict) or "case_id" not in row or "step" not in row:
                raise GuardError("Malformed report row")
            key = (row["case_id"], row["step"])
            if row.get("status") == "error":
                raise GuardError("Cannot compare incomplete runs; fix backend errors first")
            if key in entries:
                raise GuardError("Duplicate report row")
            entries[key] = row
        return entries
    old, new = indexed(before), indexed(after)
    changes = []
    for key in sorted(old.keys() | new.keys()):
        left, right = old.get(key), new.get(key)
        if left is None or right is None:
            kind = "added" if left is None else "removed"
        elif left.get("fingerprint") != right.get("fingerprint"):
            kind = "input_changed"
        elif left.get("expected") != right.get("expected"):
            kind = "expectations_changed"
        elif left.get("actual") == right.get("actual") and left.get("status") == right.get("status"):
            continue
        else:
            kind = "behavior_changed"
        changes.append({"case_id": key[0], "step": key[1], "kind": kind,
                        "before": left.get("actual") if left else None,
                        "after": right.get("actual") if right else None})
    counts_before, counts_after = _rule_counts(old), _rule_counts(new)
    rule_counts = [{"rule_id": rid, "before": counts_before.get(rid, 0), "after": counts_after.get(rid, 0)}
                   for rid in sorted(counts_before.keys() | counts_after.keys())
                   if counts_before.get(rid, 0) != counts_after.get(rid, 0)]
    return {"schema_version": 1, "before_mode": before.get("mode"),
            "after_mode": after.get("mode"), "before_label": before.get("label"),
            "after_label": after.get("label"), "changes": changes,
            "rule_counts": rule_counts,
            "dropped_to_zero": [r["rule_id"] for r in rule_counts if r["before"] > 0 and r["after"] == 0]}


def _rule_counts(indexed_rows):
    """How many sample events each rule matched. A rule that goes to zero often means it quietly stopped matching."""
    counts = {}
    for row in indexed_rows.values():
        actual = row.get("actual")
        if isinstance(actual, dict):
            rid = actual.get("rule_id") or "(no rule)"
            counts[rid] = counts.get(rid, 0) + 1
    return counts
