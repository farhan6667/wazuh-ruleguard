# Changelog

## 0.3.5: 2026-10-24

- Rewrote the README to be scannable: a short "what it does" list, a "what's new" list for the
  current release, a 30 second quick start up top, and everything else (CI guide, suite contract,
  limits, related tools) folded into collapsed sections. No content removed, only reordered and
  de-duplicated.
- Replaced the banner, the "how it works" diagram and the social preview card. All three were
  hand-coded flat SVGs or a generic dark-navy graphic; they are now a Wazuh-blue glass look (the
  product's own palette) with the real Wazuh wordmark and a trademark note, built from generated
  art composited with real text in HTML, never text drawn by an image model.
- Added the Wazuh trademark note to NOTICE, next to the existing NexaForge/SFA mark notice.

### Hardening after an adversarial review (2026-10-24)

- **`ruleguard lint` could be made to hang.** Three regular expressions backtracked with the
  square of the input length: a long `(|||...` or `[[[...` inside one element, or many `<rule `
  inside a comment. A 100 KB element took 30 seconds, and the 4 MB limit allowed hours, enough to
  stall a CI job that lints rules from a pull request. All three checks are now linear; a test
  compares them against the old patterns on 5,000 random strings to show they flag the same text.
- **`lint` crashed on some Unicode digits.** A level such as `²` passed `str.isdigit()` and then
  crashed `int()` with a traceback; Arabic-Indic digits were accepted as a valid rule id, and a
  level over 4,300 digits long hit Python's integer conversion limit. Ids and levels must now be
  ASCII digits and are reported as findings, not crashes.
- **`lint` reported false cross-file duplicates** for rule ids inside XML comments, because it
  searched the raw text. It now reads ids from the parsed rules.
- **`lint` refuses DOCTYPE and ENTITY declarations** with a clear message, and when it scans a
  folder it refuses a file that links to somewhere outside that folder.
- **Hostile or broken JSON crashed with a traceback.** Deeply nested JSON raised RecursionError,
  and a report whose case id or rule id was a list, or whose rows mixed types, crashed `compare`
  with TypeError. Reports and replays are now checked row by row; suites and reports must be
  regular files under 64 MiB; a UTF-8 byte order mark is accepted.
- **`--timeout inf` crashed** with OverflowError and `nan` was accepted. The timeout must now be
  above 0 and at most 3600 seconds. The API token must be visible ASCII, which also rules out
  header injection through the environment variable, and an invalid port in `--api` is reported.
- **Non-ASCII case ids or file names crashed output on a legacy Windows console** (cp1252, as on
  a redirected CI log). Output now falls back to escapes instead of failing.
- Any unexpected error now ends with a one-line message and exit code 2 instead of a traceback
  that could print local paths; `RULEGUARD_DEBUG=1` shows the traceback.
- Markdown summaries escape backticks and control characters as well as pipes, so a case id cannot
  close a code span and inject links into a CI summary. JUnit XML stays well formed when a case id
  contains control characters.
- **Long cases were quadratic.** One case with 5,000 events took 27 seconds to record and 54 to
  replay, because every step re-hashed the whole case. Both now take well under a second, and
  replay no longer rescans every recorded row for every case (20,000 cases: 13 s to 0.2 s).
- `ruleguard init` now writes the same two sample events as `examples/suite.json`, so the README
  quick start (init, validate, replay `examples/synthetic-before.json`) passes. Before, both cases
  errored with "Replay input differs from recorded events".
- Supply chain: the build backend is bounded (`setuptools>=77,<85`) instead of open ended, and
  `project.license` uses the SPDX string form (the table form stops building in February 2027).
  The image workflow's actions are pinned to commit SHAs, its permissions are set per job, and
  checkouts no longer keep the token. New `.github/dependabot.yml` for actions, pip and Docker.
  The CI guide now installs a release tag instead of the moving `main` branch.
- CI tests every Python version the README claims (3.10 to 3.14, Linux and Windows), lints the
  examples, and runs pinned bandit and pip-audit.
- README: softened "lints for the mistakes" to "some common mistakes", said plainly that the HTTPS
  adapter has not yet been run against a live manager, corrected the container description and
  the sample lint output. SECURITY.md lists what input is refused; the security contact link now
  points at SECURITY.md, because private vulnerability reporting is not enabled on the repository.

## 0.3.4: 2026-10-22

- **Corrected three rules in `examples/php2shell_indicators.xml` that would not have fired as
  written**, found through live `wazuh-logtest` testing on a Wazuh 4.14.7 manager with synthetic
  samples (no exploit chain, no real production data): 6 cases that should alert fired at the
  expected level, 11 normal-looking events did not alert, and 1 regression check on an older rule
  still hit. The new-PHP-file rule has not yet fired from a real FIM event, and none of this was
  tested against a real exploit.
  - The shell-spawn rule matched on a field (`parent_process`) that Linux audit's own execve
    decoder never produces, only a numeric ppid, so it could never fire. Replaced with
    `audit.exe` and `audit.cwd` (a web-docroot path you must set), narrowed to specific
    high-signal tools (`nc`, `ncat`) instead of any shell: PHP's own `exec()` routinely runs
    commands through `/bin/sh` as normal behavior, so "any shell" was too noisy to use as written.
  - The crash/OOM rules assumed a php-fpm log line that is often never collected at all. What
    usually reaches the manager is the kernel's own line, which stock Wazuh already decodes as
    rule 1010 (segfault) or 5108 (OOM kill). The rules now chain from those stock rules and match
    `php-fpm` in the message, instead of an unverified syslog placeholder.
  - The new-PHP-file rule's level dropped from 12 to 5: a site that deploys PHP often will trip
    it as routine traffic, not an incident, so it is a lead to review rather than a high-severity
    alert. Documented that the owner filter (`uname_after`) should be dropped on a per-user
    PHP-FPM setup, where files are owned by the site's own account and the filter would simply
    never match.
  - Documented that a child of stock rule 80792 ("Audit: Command") only fires when the audit key
    is registered in `etc/lists/audit-keys` with the value `command`; the shell-spawn rule now
    chains from `<if_group>audit</if_group>` instead, to avoid that trap entirely.
- New `examples/php2shell_suite.json`: a RuleGuard suite with 8 cases covering the rules above,
  both the alerts that should fire and the normal-looking events that should not. The raw event
  text is a placeholder you must replace with lines captured from your own decoders, same as the
  if_sid values and field names elsewhere in this example; it validates with `ruleguard validate`
  but has not itself been run against a live manager.

## 0.3.3: 2026-10-22

- **Fixed `examples/php2shell_indicators.xml` so it actually loads.** Five `<field>` conditions
  used alternation inside a group, such as `\.(php|phtml|php5)$` and `^(sh|bash|...)$`, without
  `type="pcre2"`. On a live Wazuh 4.14.7 manager `wazuh-analysisd -t` rejects the whole file
  (error 5107 "Syntax error on tag", then 1220 "Error loading the rules"), so anyone who loaded the
  0.3.2 example and restarted would have had a manager that would not start. All five now carry
  `type="pcre2"`. Proven one field at a time on a live engine: each fix moved the error to the
  next field, and with all five fixed the file loads with exit code 0.
- New `ruleguard lint` error, `group-alternation-without-pcre2`, for exactly that construct in
  `<field>` and `<regex>`. It is an error, not a warning, because the result is a manager that
  will not start rather than a rule that quietly never matches. On the 0.3.2 example it reports
  the same five fields the live engine rejected, and nothing else.
- New lint error `self-counting-group`: a frequency rule whose `<if_matched_group>` names a group
  the rule itself belongs to. Rules inherit the names of the enclosing `<group name="...">`, so
  this can happen without the rule having its own `<group>` tag.
- New lint error `unknown-decoder` for `<decoded_as>syslog</decoded_as>`: there is no decoder by
  that name in the stock 4.x ruleset, and the manager rejects the file.
- New lint note `audit-command-parent` for children of stock rule 80792 ("Audit: Command"): it
  only fires when `audit.key` is listed in `etc/lists/audit-keys` with the value `command`, so
  events tagged with a custom audit key never reach it.
- `ruleguard/__init__.py` reported version 0.3.0 while the package was 0.3.2. Both are now 0.3.3.

## 0.3.2: 2026-10-22

- Fixed `examples/php2shell_indicators.xml`: its php-fpm crash frequency rule referenced its own
  rule id in `if_matched_sid`, which can never fire and some managers reject as circular. Split
  it into a base rule (100212) and a separate frequency rule (100213) that counts repeats of
  100212, the pattern Wazuh's own docs use.
- The same file's "new file" rule used `if_sid 550` ("integrity checksum changed", for a modified
  file). Changed to `554` ("file added to the system"), which is the documented default FIM rule
  for a new file. The shell-spawned-by-web-server and php-fpm-crash rules had no verified default
  `if_sid` to point at (that depends on which exec-monitoring and syslog decoders you run), so
  they're now standalone placeholder rules with no `if_sid`, and the file's header comment says
  plainly which of the three base rules is confirmed against Wazuh's docs and which are not.
- New `ruleguard lint` check, `self-referencing-sid`: flags a rule whose `if_sid` or
  `if_matched_sid` points at its own id, the mistake above. Caught nothing it shouldn't on the
  rest of the repo's examples.
- Thanks to a second review pass that caught this before anyone loaded the example on a manager.

## 0.3.1: 2026-10-22

- Removed the Urdu README that shipped in 0.3.0. The project documentation stays in plain English for an international audience.
- New `examples/php2shell_indicators.xml`: a teaching example for CVE-2026-109618 and CVE-2026-109619
  (PHP core RCE, fixed in 8.5.12, 8.4.27, 8.3.36, 8.2.35). Three post-compromise indicator patterns,
  no exploit code. It lints clean with `ruleguard lint`; its expected output still needs live
  verification on a manager, same as the existing teaching example.

## 0.3.0: 2026-10-09

- `ruleguard coverage` shows which ATT&CK techniques a suite asserts and which cases assert none. `--want` lists techniques you expect to be tested and exits with 1 when one is missing. `--json` and `--markdown` write reports.
- `ruleguard lint` checks Wazuh rule XML offline for rules that load and quietly never match: PCRE-only syntax without `type="pcre2"`, `*` or `+` on a plain character, backslash expressions in `<match>`, undocumented rule elements, duplicate IDs, bad levels, missing descriptions, and notes for rules pinned to an address or hostname and for sibling rules. Errors exit with 1, `--strict` also fails on warnings, `--json` and `--markdown` write reports.
- `compare` now counts the sample events each rule matched in each run and lists rules that dropped to zero.
- `run --label` stores a free-text label (for example the Wazuh version) in the report, and the comparison shows it.
- New `docs/wazuh-gotchas.md` with the quiet failures behind these checks, and `examples/rules-with-problems.xml` to try the linter on.

## 0.2.0: 2026-10-09

- HTML reports are now readable pages (summary cards, a case table, before and after panels) instead of a JSON dump. Still one offline file with no scripts and a strict Content Security Policy.
- `--markdown` on `run` and `compare` writes a summary for CI, for example `$GITHUB_STEP_SUMMARY`.
- `ruleguard init` writes a starter suite and never overwrites a file. `ruleguard schema` prints a JSON Schema for suite files, also shipped as `ruleguard/suite.schema.json`.
- New CI guide in `docs/ci.md` with workflows for validation, a test manager run and a baseline comparison.
- Container image published to GitHub Packages (ghcr.io) on every release, built from the new Dockerfile and smoke tested in CI.
- Licence changed from MIT to Apache-2.0 for future versions, with a NOTICE file. Earlier commits stay under MIT.
- README redesigned with a banner, a how-it-works diagram and brand footer.

## 0.1.0: 2026-10-05: local prototype

Initial wazuh-ruleguard implementation, CLI, synthetic examples, documentation and unit tests.
Prepared for Python 3.10+. Local verification used Python 3.12 on Windows.
No public release or live engine compatibility certification has been completed.
