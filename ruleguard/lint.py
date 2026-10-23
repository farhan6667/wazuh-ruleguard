"""Static checks for Wazuh rule files: rules that parse fine but quietly do nothing, or will rot.

Everything here is advisory and offline. It reads rule XML, never contacts a manager, and cannot
prove that a rule works. Use it next to a real logtest run, not instead of one.
"""
import re
# Rule files come from the person running the linter, and _parse() refuses any DOCTYPE or ENTITY
# declaration before expat sees the text, so entity expansion and external entities cannot happen.
# That is why the stdlib parser is fine here without adding defusedxml as a runtime dependency.
import xml.etree.ElementTree as ET  # nosec B405
from pathlib import Path

from .core import GuardError
from .report import md_cell

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

UNESCAPED_BRACKET = re.compile(r"(?<!\\)\[")


def _has_character_class(text):
    """An unescaped [ with a ] somewhere after it. Done without a regex like \\[[^\\]]*\\], which
    backtracks quadratically on a long run of [ with no closing bracket."""
    found = UNESCAPED_BRACKET.search(text)
    return bool(found) and "]" in text[found.end():]


# Constructs that only the PCRE2 engine understands, per the Wazuh regex reference. Every check here
# must stay linear on hostile input: one element of a rule file can be megabytes long.
PCRE_ONLY = [
    (re.compile(r"\(\?").search, "a group modifier or lookaround such as (?i) or (?:"),
    (_has_character_class, "a character class like [a-z]"),
    (re.compile(r"\{[0-9]+(,[0-9]*)?\}").search, "a counted quantifier like {3} or {2,5}"),
    (re.compile(r"\\[bBAzZhHnrfxX0-9]").search, "an escape the default engine does not know (such as \\b or \\n)"),
    (re.compile(r"[*+?]\?|[*+?]\+").search, "a lazy or possessive quantifier"),
]
BACKSLASH_EXPR = re.compile(r"\\.")
# Alternation inside a group, such as \.(php|phtml)$. Seen on a live Wazuh 4.14.7 manager to make
# wazuh-analysisd reject the whole rule file (error 5107, then 1220 "Error loading the rules"), which
# stops the manager from starting. Worse than a rule that silently never matches, so it is an error.
# The first part excludes | so the engine cannot try every | as the split point. The older form took
# 30 seconds on a 100 KB element and grew with the square of the length. It matches the same text.
GROUP_ALTERNATION = re.compile(r"\([^()|]*\|[^()]*\)")
NUMBER = re.compile(r"[0-9]+")
DECLARATION = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
OS_REGEX_ELEMENTS = {"field", "regex"}


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
    if element.tag in OS_REGEX_ELEMENTS and GROUP_ALTERNATION.search(text):
        out.append(_finding("error", "group-alternation-without-pcre2", path, rule_id,
                            f"<{element.tag}> has alternation inside a group, like (a|b), but no type=\"pcre2\". The default "
                            "engine cannot compile it: wazuh-analysisd rejects the whole rule file and the manager will not "
                            "start. Add type=\"pcre2\"."))
        return out
    for found, what in PCRE_ONLY:
        if found(text):
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


def _is_number(value):
    """ASCII digits only. str.isdigit() also accepts characters such as a superscript two, which int()
    then rejects with a traceback, and Arabic-Indic digits, which Wazuh does not accept as a rule id."""
    return bool(value) and NUMBER.fullmatch(value) is not None


def _parse(text, path):
    name = Path(str(path)).name
    if DECLARATION.search(text):
        raise GuardError(f"Cannot parse {name}: it contains a DOCTYPE or ENTITY declaration, which Wazuh rule "
                         "files do not use. Refusing it rather than letting the parser expand entities.")
    try:
        # Rule files have several top-level <group> elements, so wrap them in one root to parse them.
        return ET.fromstring("<root>" + re.sub(r"^\s*<\?xml[^>]*\?>", "", text) + "</root>")  # nosec B314
    except ET.ParseError as exc:
        raise GuardError(f"Cannot parse {name}: {exc}") from None


def _rule_ids(root):
    """Numeric rule ids from the parsed tree, so a rule id inside an XML comment is not counted."""
    return [r.get("id") for r in root.iter("rule") if _is_number(r.get("id"))]


def lint_text(text, path="<text>"):
    return _lint_root(_parse(text, path), path)


def _lint_root(root, path):
    findings, seen, parents = [], {}, {}
    parent_of = {child: parent for parent in root.iter() for child in parent}
    for rule in root.iter("rule"):
        rule_id = rule.get("id")
        if not _is_number(rule_id):
            findings.append(_finding("error", "bad-id", path, rule_id, "A rule needs a numeric id."))
            continue
        if rule_id in seen:
            findings.append(_finding("error", "duplicate-id", path, rule_id, "Rule id is defined more than once in the files checked."))
        seen[rule_id] = True
        level = rule.get("level")
        # The length check comes first: int() refuses strings over 4300 digits with a ValueError.
        if not _is_number(level) or len(level.lstrip("0")) > 2 or int(level) > 16:
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
            if child.tag == "decoded_as" and (child.text or "").strip() == "syslog":
                findings.append(_finding("error", "unknown-decoder", path, rule_id,
                                         "There is no decoder named \"syslog\" in the stock Wazuh 4.x ruleset, and wazuh-analysisd "
                                         "rejects the file (Invalid decoder name). For a syslog-style line, match the program with "
                                         "<program_name> or chain from the decoder that actually handles it."))
            if child.tag in ("if_sid", "if_matched_sid"):
                refs = [p for p in re.split(r"[\s,]+", (child.text or "").strip()) if p]
                if rule_id in refs:
                    findings.append(_finding("error", "self-referencing-sid", path, rule_id,
                                             f"<{child.tag}> references the rule's own id ({rule_id}). Wazuh matches a rule against an "
                                             "earlier rule's prior alerts, never its own: this can never fire, and a manager may reject "
                                             "it as circular. Point it at the id of the rule that decodes the underlying single event."))
                if child.tag == "if_sid" and "80792" in refs:
                    findings.append(_finding("info", "audit-command-parent", path, rule_id,
                                             "Stock rule 80792 (\"Audit: Command\") only fires when audit.key is listed in "
                                             "etc/lists/audit-keys with the value \"command\". Events tagged with your own audit "
                                             "key never reach it, so a child of 80792 can silently never fire. Check your key is "
                                             "in that list, or chain from <if_group>audit</if_group> instead."))
                if child.tag == "if_sid":
                    for parent in refs:
                        parents.setdefault(parent, []).append(rule_id)
        counted = (rule.findtext("if_matched_group") or "").strip()
        if counted:
            own = {g.strip() for g in (rule.findtext("group") or "").split(",") if g.strip()}
            wrapper = parent_of.get(rule)
            if wrapper is not None and wrapper.tag == "group":
                own |= {g.strip() for g in (wrapper.get("name") or "").split(",") if g.strip()}
            if counted in own:
                findings.append(_finding("error", "self-counting-group", path, rule_id,
                                         f"The rule counts <if_matched_group>{counted}</if_matched_group> but is itself in group "
                                         f"\"{counted}\" (directly or through the enclosing <group name>, which rules inherit). Its "
                                         "own alerts feed its own count. Keep the frequency rule out of the group it counts."))
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
            base = p.resolve()
            for x in sorted(p.rglob("*.xml")):
                if not x.is_file():
                    continue
                # A link inside a rules folder that points outside it (planted in a pull request, say)
                # would otherwise be read and reported on. Such a file has to be named explicitly.
                target = x.resolve()
                if base not in target.parents:
                    raise GuardError(f"{x.name} links to a file outside {p.name}; pass it explicitly if you meant to lint it")
                files.append(x)
                if len(files) > MAX_FILES:
                    raise GuardError(f"Too many files (limit {MAX_FILES})")
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
        try:
            with f.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)  # bounded even if the file grows after it was listed
        except OSError:
            raise GuardError(f"Cannot read {f.name}") from None
        if len(raw) > MAX_BYTES:
            raise GuardError(f"{f.name} is larger than {MAX_BYTES // 1_000_000} MB")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise GuardError(f"Cannot read {f.name} as UTF-8") from None
        root = _parse(text, f)
        found = _lint_root(root, f)
        # The old raw-text regex here also counted ids inside XML comments and backtracked
        # quadratically on a long run of "<rule " with no ">".
        for rid in _rule_ids(root):
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
            lines.append(f"| {f['severity']} | `{f['code']}` | {md_cell(Path(f['file']).name)} | {md_cell(f['rule'])} | {md_cell(f['message'])} |")
    else:
        lines.append("Nothing to report.")
    return "\n".join(lines) + "\n"
