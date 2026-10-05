# Wazuh RuleGuard

**Catch detection regressions before a rule change or manager upgrade reaches production.**

RuleGuard runs a declarative corpus of raw logs against the real Wazuh 4.x logtest API,
checks expected detections and exceptions, and compares results between two environments.
Python 3.10+, zero runtime dependencies, Windows/Linux/macOS CLI.

Status: **0.1.0 prototype**. Unit and API-contract tests pass locally. No live Wazuh engine
has been used to validate this release. The included demo observations are synthetic.
Wazuh 5.x uses a different pipeline and is not supported by this adapter.

## The problem

You tune a noisy rule and the sample log passes. Did you accidentally suppress a malicious
variant? Does the rule still decode the same way after an upgrade? A repeatable corpus gives
you a reviewable answer for the samples you actually tested.

## What you get

- Positive checks: rule ID, alert flag, level, decoder, ATT&CK IDs and rule groups.
- Negative checks: forbidden rule IDs and expected non-alerts.
- Multiple events in one case reuse a logtest session for correlation. Cases are isolated.
- Unexpected session replacement is an error, preventing silent correlation resets.
- Backend warnings fail checks by default, including configuration/list loading warnings.
- JSON, JUnit XML and HTML artifacts; nonzero exits for regressions or backend errors.
- Stable comparisons omit timestamps, counters, descriptions, JWTs and raw event text.
- Input fingerprints distinguish changed test inputs from changed detection behavior.
- HTTPS certificate verification, custom CA support, blocked redirects and no automatic retries.

## Try the offline demo

From the repository directory, no install is required:

```sh
python -m ruleguard validate examples/suite.json
python -m ruleguard run examples/suite.json --replay examples/synthetic-before.json --json result.json --junit result.xml --html result.html
python -m ruleguard compare examples/synthetic-before.json examples/synthetic-after.json --json diff.json --html diff.html
```

The run should pass three checks in **offline-replay** mode. The compare command should exit
1 and identify the deliberately broken healthcheck exception. Replay checks stored observations;
it does not evaluate detection rules or establish current engine behavior.

Install the CLI with `python -m pip install .`, then use `ruleguard` instead of
`python -m ruleguard`.

## Connect a test manager

Set `WAZUH_API_TOKEN` to an existing, short-lived Wazuh API JWT using your normal secret
management process. Never put it in the suite or command arguments. Then:

```sh
ruleguard run examples/suite.json --api https://test-manager.example:55000 --ca-file manager-ca.pem --json candidate.json --junit candidate.xml
```

Load your own rules and decoders on the disposable manager first. RuleGuard does not install
rules, restart services, change production settings, or authenticate with username/password.
For the teaching example, `examples/local_rules.xml` contains custom rule IDs that must be
checked for collisions before use. Its expected output still needs live verification.

Use a least-privilege account authorized for logtest and session cleanup. The existing JWT is
used only on the specified HTTPS origin; environment proxies are ignored. No insecure TLS
switch is provided. Long suites may require a JWT lifetime that covers the run; a failed request
is not retried because a retry could duplicate correlation events.

## Suite contract

```json
{
  "schema_version": 1,
  "cases": [{
    "id": "application-login-failure",
    "events": [{
      "event": "{\"event_type\":\"login_failure\",\"username\":\"demo_user\"}",
      "location": "ruleguard",
      "log_format": "syslog",
      "expect": {"rule_id": "100100", "level": 10, "mitre_contains": ["T1110"]}
    }]
  }]
}
```

Every event needs an expectation. Supported keys: `rule_id` (string or null), `decoder`
(string or null), `level`, `alert`, `forbidden_rule_ids`, `groups_contains`, `mitre_contains`.
Lists are containment checks, not exact ordering checks. Unknown expectation/event keys fail
validation rather than silently skipping a typo. Use several events in a case to test a
sequence; use different cases for independent positive/negative scenarios.

For archived Wazuh records, use the original `full_log` as the event, not the entire alert
wrapper. Preserve its original location when your rules depend on it.

## Upgrade workflow

1. Use the same corpus against your current disposable test manager; save `baseline.json`.
2. Load the same custom rules and dependencies on the candidate manager; save `candidate.json`.
3. `ruleguard compare baseline.json candidate.json --json changes.json --html changes.html`.
4. Review every change; a changed rule ID is not automatically a vulnerability or regression.
5. Follow up with ingestion and alert-delivery tests before rolling out an upgrade.

Exit codes: 0 checks pass/no differences, 1 assertions/differences/backend run errors, 2
invalid configuration/input or output failure, 130 interruption. `--allow-warnings` explicitly
permits backend warnings. It should only be used after reviewing the manager locally.

## Limits and data handling

Logtest does not prove production log collection, indexing, alert delivery or live correlation
will work. Sequences run as fast as the API responds; this is not a virtual-clock simulator and
does not exercise delays, out-of-order delivery or production traffic volume. The corpus defines
the coverage; passing a small corpus cannot establish detection quality across your fleet.

Reports exclude raw event text and session/JWT tokens. Case names, rule metadata and fingerprints
can still be sensitive: inspect artifacts before sharing them. Inputs are sent only to the manager
you specify. Outputs cannot overwrite inputs. Cleanup is attempted even on run failure; a process
crash or network outage may leave a session until Wazuh expires it.

## Related tools

[wazuhdevenv](https://github.com/zbalkan/wazuhdevenv) provides an established testing development
environment. [wazuhtester](https://pypi.org/project/wazuhtester/) offers a socket client and pytest
integration. RuleGuard focuses on JSON scenario contracts, HTTPS manager access, explicit
negative cases and portable before/after artifacts. Evaluate those tools too; this is not a
claim that their feature sets lack every capability listed here.

API behavior follows [Wazuh's official logtest documentation](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).

## Development

```sh
python -m unittest discover -s tests -v
```

Contributions most useful before a release: live-manager compatibility results with the version
and sanitized fixtures, negative cases for common exceptions, and real correlation scenarios.
Do not upload organization logs or credentials. See CONTRIBUTING.md and SECURITY.md.

Built by [Syed Farhan Ahmed](https://farhan6667.github.io/portfolio/).
