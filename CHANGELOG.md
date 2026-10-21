# Changelog

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
