import argparse
import html
import json
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

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


def write_html(value, path):
    escaped = html.escape(json.dumps(value, indent=2))
    Path(path).write_text("<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>RuleGuard report</title><style>body{background:#101925;color:#e8edf4;font:16px system-ui;"
        "max-width:1000px;margin:40px auto;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere;"
        "background:#172538;padding:24px;border-radius:12px}h1{color:#6fe3b1}</style>"
        "<h1>Wazuh RuleGuard</h1><p>Detection regression report. Mode and failures appear below.</p>"
        f"<pre>{escaped}</pre></html>", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Test Wazuh 4.x detections; compare behavior across changes.")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Check suite before contacting a manager")
    validate.add_argument("suite")
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
    run.add_argument("--html")
    diff = commands.add_parser("compare")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--json", required=True, dest="json_path")
    diff.add_argument("--html")
    args = parser.parse_args(argv)
    try:
        inputs = [getattr(args, name, None) for name in ("suite", "replay", "before", "after", "ca_file")]
        outputs = [getattr(args, name, None) for name in ("json_path", "junit", "html")]
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
                write_html(report, args.html)
            print(f"{len(report['changes'])} changes; review input_changed separately from behavior_changed")
            return 1 if report["changes"] else 0
        suite = load_suite(Path(args.suite))
        if args.replay:
            backend = ReplayBackend(read_json(args.replay))
        else:
            backend = APIBackend(args.api, os.environ.get("WAZUH_API_TOKEN"), args.ca_file, args.timeout)
        report = run_suite(suite, backend, args.allow_warnings)
        write_json(args.json_path, report)
        if args.junit:
            junit(report, args.junit)
        if args.html:
            write_html(report, args.html)
        print(f"{report['mode']}: {report['passed']} passed, {report['failed']} failed/error")
        return 1 if report["failed"] else 0
    except (GuardError, OSError) as exc:
        print(f"ruleguard: {exc if isinstance(exc, GuardError) else 'Cannot write output file'}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
