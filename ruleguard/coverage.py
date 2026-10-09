"""Which ATT&CK techniques does a suite actually test? Purple team style coverage, computed from the suite alone."""
import re

from .core import GuardError

TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def parse_wanted(values):
    wanted = []
    for raw in values or []:
        for item in str(raw).split(","):
            item = item.strip().upper()
            if not item:
                continue
            if not TECHNIQUE.match(item):
                raise GuardError(f"Not an ATT&CK technique ID: {item[:20]} (expected something like T1110 or T1558.003)")
            if item not in wanted:
                wanted.append(item)
    return wanted


def coverage(suite, wanted=None):
    """Return which techniques the suite asserts, which cases assert none, and which wanted techniques have no test.

    A wanted parent technique (T1558) counts as tested when any of its sub-techniques (T1558.003) is asserted.
    A wanted sub-technique needs an exact match.
    """
    techniques, untagged, rules = {}, [], {}
    for case in suite["cases"]:
        asserted = set()
        for event in case["events"]:
            expect = event["expect"]
            asserted.update(expect.get("mitre_contains", []))
            if expect.get("rule_id"):
                rules.setdefault(expect["rule_id"], set()).add(case["id"])
        for tid in sorted(asserted):
            techniques.setdefault(tid, []).append(case["id"])
        if not asserted:
            untagged.append(case["id"])
    covered = sorted(techniques)
    missing = []
    for want in wanted or []:
        hit = want in techniques or ("." not in want and any(t.startswith(want + ".") for t in techniques))
        if not hit:
            missing.append(want)
    return {
        "schema_version": 1,
        "cases": len(suite["cases"]),
        "techniques": [{"technique": t, "cases": techniques[t]} for t in covered],
        "cases_without_technique": untagged,
        "wanted": list(wanted or []),
        "wanted_missing": missing,
        "rules_asserted": sorted(rules),
    }


def text_report(report):
    n = len(report["techniques"])
    lines = [f"{report['cases']} cases, {n} technique{'s' if n != 1 else ''} asserted"]
    for t in report["techniques"]:
        lines.append(f"  {t['technique']:<10} {', '.join(t['cases'])}")
    if report["cases_without_technique"]:
        lines.append("Cases that assert no technique: " + ", ".join(report["cases_without_technique"]))
    if report["wanted"]:
        if report["wanted_missing"]:
            lines.append("Wanted but not tested: " + ", ".join(report["wanted_missing"]))
        else:
            lines.append("Every wanted technique has at least one test")
    return "\n".join(lines)


def markdown(report):
    lines = ["## Wazuh RuleGuard technique coverage", "",
             f"**{len(report['techniques'])} techniques asserted across {report['cases']} cases**", ""]
    if report["techniques"]:
        lines += ["| Technique | Cases |", "|---|---|"]
        lines += [f"| `{t['technique']}` | {', '.join('`%s`' % c for c in t['cases'])} |" for t in report["techniques"]]
    if report["wanted"]:
        lines += ["", "**Wanted but not tested:** " + (", ".join(f"`{t}`" for t in report["wanted_missing"]) or "none")]
    if report["cases_without_technique"]:
        lines += ["", "Cases that assert no technique: " + ", ".join(f"`{c}`" for c in report["cases_without_technique"])]
    return "\n".join(lines) + "\n"
