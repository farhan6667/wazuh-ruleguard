# Test a broken healthcheck exception

This walkthrough uses synthetic observations. You can run it without a Wazuh
manager to learn the suite format, report output and comparison commands.

Run these commands from the repository directory with Python 3.10 or newer:

```sh
python -m ruleguard validate examples/suite.json
python -m ruleguard run examples/suite.json --replay examples/synthetic-before.json --json result.json --junit result.xml --html result.html
python -m ruleguard compare examples/synthetic-before.json examples/synthetic-after.json --json diff.json --html diff.html
```

Validation should exit 0. The replay should pass three checks and exit 0. Open
`result.html` to inspect the observations and their expectations.

The comparison should exit 1 because the second fixture changes the healthcheck
exception from rule `100101` to rule `100100`. Open `diff.html` to inspect the
changed behavior. In CI, that exit code can stop a job until someone reviews it.

Replay reads saved observations. It doesn't execute the XML in
`examples/local_rules.xml` or prove that those rules work on a manager.

To collect real observations, load your rules and decoders on an authorized test
manager, set `WAZUH_API_TOKEN` through your normal secret handling process, and run:

```sh
python -m ruleguard run examples/suite.json --api https://test-manager.example:55000 --ca-file manager-ca.pem --json baseline.json
```

Replace the hostname, CA file and suite with your environment's values. Review
the output against the actual Wazuh version before treating it as a baseline.
The [README](../README.md) explains session behavior and coverage limits.
