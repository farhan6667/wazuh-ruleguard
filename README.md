<h1 align="center"><img src="docs/img/banner.svg" alt="Wazuh RuleGuard: check whether a rule change breaks the detections you expect" width="100%"></h1>

<p align="center">
  <a href="https://github.com/farhan6667/wazuh-ruleguard/actions/workflows/ci.yml"><img src="https://github.com/farhan6667/wazuh-ruleguard/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-3776ab.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/runtime%20dependencies-none-2ea44f.svg" alt="No runtime dependencies">
  <img src="https://img.shields.io/badge/status-prototype-00d1ff.svg" alt="Status: prototype">
</p>


Check whether a Wazuh rule change breaks the detections you expect.

RuleGuard sends your sample logs to the Wazuh 4.x logtest API and checks the
results against a JSON suite. Run the same suite before and after a change to see
which detections moved. Reports work in a terminal, CI job or browser.

Requires Python 3.10 or newer. There are no runtime dependencies.

Version 0.1.0 is a prototype. Local tests cover the client and CLI on Windows with
Python 3.12. Live Wazuh validation is still pending, and the demo observations are
synthetic. This adapter supports the 4.x API contract; Wazuh 5.x needs a different
adapter.

## At a glance

| | |
|---|---|
| **Tests** | Wazuh 4.x detection changes against a JSON suite of sample logs |
| **Checks** | Rule ID, alert flag, level, decoder, ATT&CK IDs, groups, forbidden rules, sequences |
| **Reports** | JSON, JUnit XML and an offline HTML page, plus a baseline vs candidate comparison |
| **Runs on** | Python 3.10+, no runtime dependencies, offline replay mode for the demo |
| **Status** | Prototype. Live Wazuh validation is still pending |

## Why keep a test corpus?

Suppose you add an exception for a healthcheck account. The healthcheck should
stop alerting, but an ordinary failed login should still trigger its rule. Keep
both samples in a suite so the next rule edit tests both outcomes.

A manager upgrade can also change decoding or rule selection. Saving a baseline
lets you review those changes for the samples in your corpus.

## Checks and reports

Each event can check the rule ID, alert flag, level and decoder. You can also
require ATT&CK IDs or rule groups, forbid particular rules, or expect no alert.
Events within one case share a logtest session for correlation. Each case gets
its own session, and an unexpected session replacement fails the run.

Backend warnings fail checks by default, including warnings about configuration
or list loading. JSON, JUnit XML and offline HTML reports give you a result to
review. The comparison records changed inputs separately from changed behavior.
It omits timestamps, counters, descriptions, JWTs and raw event text.

HTTPS certificates are verified. Custom CA files are supported, redirects are
blocked and requests aren't retried automatically.

## How it works

<p align="center"><img src="docs/img/how-it-works.svg" width="100%" alt="How Wazuh RuleGuard works, in four steps"></p>

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

Set `WAZUH_API_TOKEN` to an existing, temporary Wazuh API JWT using your normal secret
management process. Never put it in the suite or command arguments. Then:

```sh
ruleguard run examples/suite.json --api https://test-manager.example:55000 --ca-file manager-ca.pem --json candidate.json --junit candidate.xml
```

Load your own rules and decoders on the disposable manager first. RuleGuard does not install
rules, restart services, change production settings, or authenticate with username/password.
For the teaching example, `examples/local_rules.xml` contains custom rule IDs that must be
checked for collisions before use. Its expected output still needs live verification.

Use a account with only the required permissions authorized for logtest and session cleanup. The existing JWT is
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
5. Follow up with ingestion and alert delivery tests before rolling out an upgrade.

Exit codes: 0 checks pass/no differences, 1 assertions/differences/backend run errors, 2
invalid configuration/input or output failure, 130 interruption. `--allow-warnings` explicitly
permits backend warnings. It should only be used after reviewing the manager locally.

## Limits and data handling

Logtest does not prove production log collection, indexing, alert delivery or live correlation
will work. Sequences run as fast as the API responds; this is not a simulator with a virtual clock and
does not exercise delays, events arriving out of order or production traffic volume. The corpus defines
the coverage; passing a small corpus cannot establish detection quality across your fleet.

Reports exclude raw event text and session/JWT tokens. Case names, rule metadata and fingerprints
can still be sensitive: inspect artifacts before sharing them. Inputs are sent only to the manager
you specify. Outputs cannot overwrite inputs. Cleanup is attempted even on run failure; a process
crash or network outage may leave a session until Wazuh expires it.

## Related tools

[wazuhdevenv](https://github.com/zbalkan/wazuhdevenv) provides an established testing development
environment. [wazuhtester](https://pypi.org/project/wazuhtester/) offers a socket client and pytest
integration. RuleGuard focuses on JSON scenario contracts, HTTPS manager access, explicit
negative cases and reports for comparing runs. Compare the available tools against your workflow before choosing one.

API behavior follows [Wazuh's official logtest documentation](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).

## Development

```sh
python -m unittest discover -s tests -v
```

Contributions most useful before a release: live manager compatibility results with the version
and sanitized fixtures, negative cases for common exceptions, and real correlation scenarios.
Do not upload organization logs or credentials. See [contribution notes](CONTRIBUTING.md) and [security notes](SECURITY.md).


For a walkthrough with expected exit codes, see [the demo guide](docs/demo.md).

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for the attribution and trademark note.

---

<div align="center">

<a href="https://nexaforge.eu.cc/">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/brand/nexaforge-lockup-dark.webp">
    <img src="docs/img/brand/nexaforge-lockup-light.webp" height="48" alt="NexaForge">
  </picture>
</a>
&nbsp;&nbsp;
<a href="https://farhan6667.github.io/portfolio/"><img src="docs/img/brand/sfa-logo.webp" height="64" alt="SFA logo"></a>

**Built by [Syed Farhan Ahmed](https://github.com/farhan6667) (SFA)** at **[NexaForge](https://nexaforge.eu.cc/)**<br>
Cyber security · Vibe coding · Web development and IT infrastructure

[Website](https://nexaforge.eu.cc/) ·
[LinkedIn](https://www.linkedin.com/in/sfa6667) ·
[Portfolio](https://farhan6667.github.io/portfolio/) ·
[Email](mailto:nexaforge.services@gmail.com)

</div>
