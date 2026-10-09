import argparse
import json
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
from importlib import resources

from . import coverage as cover
from . import lint as linting
from . import report as views
from .backends import APIBackend, ReplayBackend
from .core import GuardError, compare, load_suite, run_suite


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise GuardError("Cannot read JSON input") from None


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def junit(report, path):
    root = ET.Element("testsuite", name="ruleguard", tests=str(len(report["results"])),
                      failures=str(sum(r["status"] == "fail" for r in report["results"])),
                      errors=str(sum(r["status"] == "error" for r in report["results"])))
    for row in report["results"]:
        case = ET.SubElement(root, "testcase", classname=row["case_id"], name=f"step-{row['step']}")
        if row["status"] != "pass":
            ET.SubElement(case, "error" if row["status"] == "error" else "failure").text = "; ".join(row["failures"])
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def write_text(path, text):
    Path(path).write_text(text, encoding="utf-8")


STARTER = {
    "schema_version": 1,
    "cases": [
        {
            "id": "unexpected-login-failure",
            "events": [{
                "event": "{\"event_type\":\"login_failure\",\"username\":\"demo_user\"}",
                "location": "ruleguard", "log_format": "syslog",
                "expect": {"rule_id": "100100", "level": 10, "mitre_contains": ["T1110"]},
            }],
        },
        {
            "id": "healthcheck-exception",
            "events": [{
                "event": "{\"event_type\":\"login_failure\",\"username\":\"healthcheck\"}",
                "location": "ruleguard", "log_format": "syslog",
                "expect": {"rule_id": "100101", "alert": False},
            }],
        },
    ],
}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Test Wazuh 4.x detections; compare behavior across changes.")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Check suite before contacting a manager")
    validate.add_argument("suite")
    init = commands.add_parser("init", help="Write a starter suite to edit (never overwrites)")
    init.add_argument("path", nargs="?", default="suite.json")
    lint = commands.add_parser("lint", help="Static checks on Wazuh rule XML for rules that parse but quietly do nothing")
    lint.add_argument("paths", nargs="+", help="Rule files or folders (all .xml files inside)")
    lint.add_argument("--strict", action="store_true", help="Exit 1 on warnings too, not only on errors")
    lint.add_argument("--json", dest="json_path")
    lint.add_argument("--markdown")
    cov = commands.add_parser("coverage", help="Show which ATT&CK techniques a suite tests, and which wanted ones it does not")
    cov.add_argument("suite")
    cov.add_argument("--want", action="append", help="Technique IDs you expect to be tested, repeatable or comma separated, for example T1110,T1558.003")
    cov.add_argument("--json", dest="json_path")
    cov.add_argument("--markdown")
    commands.add_parser("schema", help="Print the JSON Schema for suite files (for editor validation)")
    run = commands.add_parser("run")
    run.add_argument("suite")
    source = run.add_mutually_exclusive_group(required=True)
    source.add_argument("--api", help="HTTPS Wazuh 4.x manager origin")
    source.add_argument("--replay", help="Offline recorded report; does not run Wazuh")
    run.add_argument("--ca-file")
    run.add_argument("--timeout", type=float, default=15)
    run.add_argument("--allow-warnings", action="store_true")
    run.add_argument("--json", required=True, dest="json_path")
    run.add_argument("--junit")
    run.add_argument("--label", help="Free text saved in the report, for example the Wazuh version it ran on")
    run.add_argument("--html")
    run.add_argument("--markdown", help="Markdown summary, for example for $GITHUB_STEP_SUMMARY")
    diff = commands.add_parser("compare")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--json", required=True, dest="json_path")
    diff.add_argument("--html")
    diff.add_argument("--markdown", help="Markdown summary of the changes")
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            print(resources.files("ruleguard").joinpath("suite.schema.json").read_text(encoding="utf-8"), end="")
            return 0
        if args.command == "init":
            target = Path(args.path)
            try:
                with target.open("x", encoding="utf-8") as stream:
                    stream.write(json.dumps({"$schema": "https://raw.githubusercontent.com/farhan6667/wazuh-ruleguard/main/ruleguard/suite.schema.json", **STARTER}, indent=2) + "\n")
            except FileExistsError:
                raise GuardError("Refusing to overwrite an existing file") from None
            print(f"Wrote {target}. Edit the sample events, then run: ruleguard validate {target}")
            return 0
        if args.command == "coverage":
            outs = [Path(p).resolve() for p in (args.json_path, args.markdown) if p]
            if Path(args.suite).resolve() in outs or len(outs) != len(set(outs)):
                raise GuardError("Outputs must differ from inputs and each other")
            report = cover.coverage(load_suite(Path(args.suite)), cover.parse_wanted(args.want))
            print(cover.text_report(report))
            if args.json_path:
                write_json(args.json_path, report)
            if args.markdown:
                write_text(args.markdown, cover.markdown(report))
            return 1 if report["wanted_missing"] else 0
        if args.command == "lint":
            files = linting.collect(args.paths)
            outs = [Path(p).resolve() for p in (args.json_path, args.markdown) if p]
            if any(o in {f.resolve() for f in files} for o in outs) or len(outs) != len(set(outs)):
                raise GuardError("Outputs must differ from inputs and each other")
            findings = linting.lint_paths(args.paths)
            print(linting.text_report(findings))
            if args.json_path:
                write_json(args.json_path, {"schema_version": 1, "summary": linting.summary(findings), "findings": findings})
            if args.markdown:
                write_text(args.markdown, linting.markdown(findings))
            counts = linting.summary(findings)
            return 1 if counts["error"] or (args.strict and counts["warning"]) else 0
        inputs = [getattr(args, name, None) for name in ("suite", "replay", "before", "after", "ca_file")]
        outputs = [getattr(args, name, None) for name in ("json_path", "junit", "html", "markdown")]
        input_paths = {Path(p).resolve() for p in inputs if p}
        output_paths = [Path(p).resolve() for p in outputs if p]
        if any(p in input_paths for p in output_paths) or len(output_paths) != len(set(output_paths)):
            raise GuardError("Outputs must differ from inputs and each other")
        if args.command == "validate":
            suite = load_suite(Path(args.suite))
            print(f"Valid suite: {len(suite['cases'])} cases")
            return 0
        if args.command == "compare":
            report = compare(read_json(args.before), read_json(args.after))
            write_json(args.json_path, report)
            if args.html:
                write_text(args.html, views.compare_html(report))
            if args.markdown:
                write_text(args.markdown, views.compare_markdown(report))
            print(f"{len(report['changes'])} changes; review input_changed separately from behavior_changed")
            for rid in report["dropped_to_zero"]:
                print(f"rule {rid} matched no sample events in the second run")
            return 1 if report["changes"] else 0
        suite = load_suite(Path(args.suite))
        if args.replay:
            backend = ReplayBackend(read_json(args.replay))
        else:
            backend = APIBackend(args.api, os.environ.get("WAZUH_API_TOKEN"), args.ca_file, args.timeout)
        report = run_suite(suite, backend, args.allow_warnings)
        if args.label:
            label = "".join(ch for ch in args.label if ch.isprintable())[:80].strip()
            if label:
                report["label"] = label
        write_json(args.json_path, report)
        if args.junit:
            junit(report, args.junit)
        if args.html:
            write_text(args.html, views.run_html(report))
        if args.markdown:
            write_text(args.markdown, views.run_markdown(report))
        print(f"{report['mode']}: {report['passed']} passed, {report['failed']} failed/error")
        return 1 if report["failed"] else 0
    except (GuardError, OSError) as exc:
        print(f"ruleguard: {exc if isinstance(exc, GuardError) else 'Cannot write output file'}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
