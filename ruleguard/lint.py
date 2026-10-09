"""Static checks for Wazuh rule files: rules that parse fine but quietly do nothing, or will rot.

Everything here is advisory and offline. It reads rule XML, never contacts a manager, and cannot
prove that a rule works. Use it next to a real logtest run, not instead of one.
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .core import GuardError

MAX_FILES = 500
MAX_BYTES = 4_000_000

# Elements documented for <rule> in the Wazuh rules syntax reference.
VALID_RULE_ELEMENTS = {
    "match", "regex", "decoded_as", "category", "field", "srcip", "dstip", "srcport", "dstport", "data",
    "extra_data", "user", "system_name", "program_name", "protocol", "hostname", "time", "weekday", "id",
    "url", "location", "action", "status", "srcgeoip", "dstgeoip",
    "if_sid", "if_group", "if_level", "if_matched_sid", "if_matched_group",
    "description", "info", "group", "mitre", "list", "options", "check_diff", "var",
} | {f"{p}_{n}" for p in ("same", "different") for n in (
    "id", "srcip", "dstip", "srcport", "dstport", "location", "srcuser", "user", "field", "protocol",
    "action", "data", "extra_data", "status", "system_name", "url", "srcgeoip", "dstgeoip")}

PATTERN_ELEMENTS = {"match", "regex", "field", "data", "extra_data", "user", "system_name", "program_name",
                    "protocol", "hostname", "id", "url", "location", "action", "status"}
PINNED_ELEMENTS = {"srcip", "dstip", "hostname", "system_name"}

# Constructs that only the PCRE2 engine understands, per the Wazuh regex reference.
PCRE_ONLY = [
    (re.compile(r"\(\?"), "a group modifier or lookaround such as (?i) or (?:"),
    (re.compile(r"(?<!\\)\[[^\]]*\]"), "a character class like [a-z]"),
    (re.compile(r"\{\d+(,\d*)?\}"), "a counted quantifier like {3} or {2,5}"),
    (re.compile(r"\\[bBAzZhHnrfxX]|\\\d"), "an escape the default engine does not know (such as \\b or \\n)"),
    (re.compile(r"[*+?]\?|[*+?]\+"), "a lazy or possessive quantifier"),
]
BACKSLASH_EXPR = re.compile(r"\\.")


class Finding(dict):
    """severity (error, warning, info), code, rule, file, message."""


def _finding(severity, code, file, rule, message):
    return Finding(severity=severity, code=code, file=str(file), rule=rule, message=message)


def _bare_quantifier(pattern):
    """True when * or + follows something that is not a backslash expression (the default engine ignores or rejects it)."""
    stripped = BACKSLASH_EXPR.sub("\u0000", pattern)
    return bool(re.search(r"[^\u0000][*+]", stripped)) or stripped.startswith(("*", "+"))


def _pattern_findings(path, rule_id, element):
    text = element.text or ""
    engine = (element.get("type") or "").lower()
    if "pcre2" in engine:
        return []
    out = []
    for rx, what in PCRE_ONLY:
        if rx.search(text):
            out.append(_finding("warning", "pcre-syntax-without-type", path, rule_id,
                                f"<{element.tag}> uses {what} but has no type=\"pcre2\". The default engine does not support it, "
                                "so the rule can parse cleanly and still never match."))
            break
    if element.tag == "match" and BACKSLASH_EXPR.search(text):
        out.append(_finding("warning", "backslash-in-match", path, rule_id,
                            "<match> is the basic matcher and does not treat backslash expressions like \\d or \\w as patterns. "
                            "Use <regex>, or add type=\"pcre2\"."))
    elif element.tag == "regex" and _bare_quantifier(text):
        out.append(_finding("warning", "bare-quantifier", path, rule_id,
                            "<regex> applies * or + to a plain character. The default engine only allows them after a backslash "
                            "expression such as \\w+ or \\d+. Use type=\"pcre2\" if you meant a full regular expression."))
    return out


def lint_text(text, path="<text>"):
    try:
        root = ET.fromstring("<root>" + re.sub(r"^\s*<\?xml[^>]*\?>", "", text) + "</root>")
    except ET.ParseError as exc:
        raise GuardError(f"Cannot parse {Path(str(path)).name}: {exc}") from None
    findings, seen, parents = [], {}, {}
    for rule in root.iter("rule"):
        rule_id = rule.get("id")
        if not rule_id or not rule_id.isdigit():
            findings.append(_finding("error", "bad-id", path, rule_id, "A rule needs a numeric id."))
            continue
        if rule_id in seen:
            findings.append(_finding("error", "duplicate-id", path, rule_id, "Rule id is defined more than once in the files checked."))
        seen[rule_id] = True
        level = rule.get("level")
        if level is None or not level.isdigit() or not 0 <= int(level) <= 16:
            findings.append(_finding("error", "bad-level", path, rule_id, "level must be a whole number from 0 to 16."))
        for child in rule:
            if child.tag not in VALID_RULE_ELEMENTS:
                findings.append(_finding("warning", "unknown-element", path, rule_id,
                                         f"<{child.tag}> is not a documented element for a rule. An invalid tag can stop the manager "
                                         "from starting, so check it against the Wazuh rules syntax reference for your version."))
            if child.tag in PATTERN_ELEMENTS:
                findings += _pattern_findings(path, rule_id, child)
            if child.tag in PINNED_ELEMENTS and (child.text or "").strip():
                findings.append(_finding("info", "pinned-identifier", path, rule_id,
                                         f"<{child.tag}> is pinned to a specific value. If that machine is rebuilt or renamed the rule can "
                                         "stop matching without any error, so check now and then that it still matches something."))
            if child.tag == "field" and (child.get("name") or "").startswith(("agent.", "agent_")):
                findings.append(_finding("info", "pinned-identifier", path, rule_id,
                                         "A field condition on an agent identifier can rot after rebuilds. Check it still matches."))
            if child.tag == "if_sid":
                for parent in re.split(r"[\s,]+", (child.text or "").strip()):
                    if parent:
                        parents.setdefault(parent, []).append(rule_id)
        if rule.find("description") is None and rule.get("noalert") != "1":
            findings.append(_finding("warning", "no-description", path, rule_id, "The rule has no <description>, so its alerts will be hard to read."))
    for parent, kids in sorted(parents.items()):
        # Only worth a note for parents defined in the files being checked; a stock parent with many children is normal.
        if len(kids) > 1 and parent in seen:
            findings.append(_finding("info", "sibling-rules", path, ",".join(kids),
                                     f"{len(kids)} rules hang off if_sid {parent}. When several siblings could match, only one is "
                                     "reported, so test them one at a time and do not read a missing alert as a dead rule."))
    return findings


def collect(paths):
    files = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files += sorted(x for x in p.rglob("*.xml") if x.is_file())
        elif p.is_file():
            files.append(p)
        else:
            raise GuardError("Cannot read a rule file or folder")
    if not files:
        raise GuardError("No .xml rule files found")
    if len(files) > MAX_FILES:
        raise GuardError(f"Too many files (limit {MAX_FILES})")
    return files


def lint_paths(paths):
    findings, ids = [], {}
    for f in collect(paths):
        if f.stat().st_size > MAX_BYTES:
            raise GuardError(f"{f.name} is larger than {MAX_BYTES // 1_000_000} MB")
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            raise GuardError(f"Cannot read {f.name} as UTF-8") from None
        found = lint_text(text, f)
        for rid in re.findall(r"""<rule\s+[^>]*\bid=["'](\d+)["']""", text):
            if rid in ids and ids[rid] != str(f):
                found.append(_finding("error", "duplicate-id", f, rid, f"Rule id is also defined in {Path(ids[rid]).name}."))
            ids.setdefault(rid, str(f))
        findings += found
    return findings


def summary(findings):
    return {s: sum(1 for f in findings if f["severity"] == s) for s in ("error", "warning", "info")}


def text_report(findings):
    lines = [f"{f['severity']:<7} {f['code']:<24} {Path(f['file']).name} rule {f['rule']}: {f['message']}" for f in findings]
    s = summary(findings)
    lines.append(f"{s['error']} errors, {s['warning']} warnings, {s['info']} notes")
    return "\n".join(lines)


def markdown(findings):
    s = summary(findings)
    lines = ["## Wazuh RuleGuard lint", "", f"**{s['error']} errors, {s['warning']} warnings, {s['info']} notes**", ""]
    if findings:
        lines += ["| Severity | Check | File | Rule | What to look at |", "|---|---|---|---|---|"]
        for f in findings:
            msg = f["message"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | `{f['code']}` | {Path(f['file']).name} | {f['rule']} | {msg} |")
    else:
        lines.append("Nothing to report.")
    return "\n".join(lines) + "\n"
