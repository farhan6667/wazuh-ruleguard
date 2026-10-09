# Wazuh rule testing gotchas

These notes come from running a Wazuh 4.x deployment for several months and tuning its rules. They are the things that cost the most time, written down so they cost you less. Examples use invented rule IDs such as 100100. Where a point was never confirmed, it says so.

The common thread: **the dangerous failures are quiet ones.** A rule that looks right in review and does nothing is worse than a rule that errors, because nothing tells you it is dead.

## Rules that load and never match

**A regular expression without the right engine.** The default engine supports a small syntax: `\w`, `\d`, `\s`, `\p`, `^`, `$`, `|`, and `*` or `+` only after a backslash expression. Character classes like `[a-z]`, counted quantifiers like `{3}`, groups, lookarounds and `(?i)` need `type="pcre2"` on the element. Without it a rule can parse cleanly and never fire. `ruleguard lint` flags these.

**Matching on text the engine never sees.** The predecoder pulls the syslog timestamp, host and program name into separate fields before matching, so a text match on the raw line will not find the hostname. Use the decoded fields instead.

**A tag that works somewhere else.** An invalid condition tag can stop the analysis daemon from starting, so the manager does not come back and no agents connect. Seeing a tag used in a stock rule is not evidence it is valid in yours, because a stock decoder may fill the field through a different mechanism. Check tags against the rules syntax reference for your version, and run `wazuh-analysisd -t` before every restart. It exits non zero on a syntax error. It does not tell you a rule will match, only that the ruleset loads.

**Sibling rules under one parent.** When several child rules hang off the same parent and more than one could match, only one is reported. During debugging a chain of probe rules looked dead when the data was fine. Test one at a time. `ruleguard lint` leaves a note when it sees siblings.

## Testing

**Verify by firing count, not by reading.** The only trustworthy check that a rule works is a non zero match count in a window where the pattern is known to be present. This is what a suite of sample logs gives you, and it is why `ruleguard compare` now lists rules that matched nothing in the second run.

**A documented rule set is not the deployed rule set.** One review document described suppression rules that were never installed, and the real ones lived in a different ID range. List what is loaded on the manager instead of trusting the design document.

**Piping into the CLI.** In one deployment, `wazuh-logtest -q` fed from a pipe or a redirect printed nothing at all, with no error and exit status zero, although it worked interactively. The cause was never established, so treat this as unverified. If you script rule checks, plan for it: RuleGuard talks to the logtest HTTP API instead, so it does not depend on that.

**Restarts are not free.** Each manager restart is a short blind window across every agent. Agents buffer and resend, so events were not lost, but five restarts in an afternoon is worth avoiding. Plan your test cycle. After a restart, confirm there is exactly one database process, because a plain restart once left two running and deadlocked, and no alerts were written for days. Stop, confirm zero, start, confirm one.

## Tuning that holds up

**Measure before you apply.** Replay recent alerts through a candidate suppression and count what it would hide and what survives. A number beats a guess, and it caught one pattern that would have hidden a real detection path. [Wazuh NoiseLens](https://github.com/farhan6667/wazuh-noiselens) does this.

**Narrow beats broad, and lowering a level beats deleting.** Setting a level to 0 keeps the event in the archive and keeps the tuning visible later.

**Never suppress on an identifier that means different things on different hosts.** A numeric user ID looked like a clean suppression until it was checked host by host and turned out to be a different account on nearly every machine. Check what the identifier means on every host before you decide.

**Scoped tuning rots.** A rule that downgraded findings from one authorised source was keyed to that machine's address. The machine was rebuilt on a new address and the rule quietly stopped matching. Anything keyed to an address, hostname or account needs an occasional check that it still matches something. `ruleguard lint` marks these as notes.

**Your own tools will trip your own detections.** A high severity rule fired on every host within two minutes, and the cause was the team's own scanning script. Before raising an alarm on a fleet wide simultaneous hit, check whether it lines up with your own activity.

**Tests leave real alerts behind.** Lowering a threshold to test a rule produces a genuine high severity alert that is indistinguishable from a real one a day later. Write down test induced alerts when they happen.

## A short checklist before you change a rule

1. `ruleguard lint` the rule files and read every warning.
2. `wazuh-analysisd -t` on the manager.
3. Run the suite on the current manager and save `baseline.json` with `--label` set to the Wazuh version.
4. Make the change, load it on a disposable manager, run the suite again with a new label.
5. `ruleguard compare` the two. Read the rules that matched nothing in the second run first.
6. After a real restart, confirm the rule has a non zero count against live data.
