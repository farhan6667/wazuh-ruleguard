# Run RuleGuard in CI

RuleGuard exits with a code a pipeline understands: 0 when every check passes, 1 when a check fails or a comparison finds differences, and 2 when the input or configuration is invalid. It can also write JUnit XML and a Markdown summary, so a pull request shows what changed without anyone opening a file.

This page is a recipe, not a promise. Like the rest of the project it has been exercised against synthetic data only. Test it on a disposable manager before you trust it.

## 1. Check the suite on every pull request (no Wazuh needed)

Validation and the offline replay need nothing installed except Python. This catches typos in a suite and keeps the example fixtures honest.

```yaml
name: ruleguard-suite
on: [pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: python -m pip install git+https://github.com/farhan6667/wazuh-ruleguard
      - run: ruleguard validate tests/wazuh/suite.json
```

## 2. Run the suite against a test manager

Real checks need the logtest API of a Wazuh 4.x manager you are allowed to test against. Use a disposable or staging manager, never production. The runner must be able to reach it, so a self-hosted runner inside your network is usually the right choice.

Store a short-lived Wazuh API token as a repository secret named `WAZUH_API_TOKEN`. RuleGuard reads it from the environment and never from an argument or a file.

```yaml
name: ruleguard-manager
on: [pull_request]
jobs:
  detections:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: python -m pip install git+https://github.com/farhan6667/wazuh-ruleguard
      - name: Run the detection suite
        env:
          WAZUH_API_TOKEN: ${{ secrets.WAZUH_API_TOKEN }}
        run: >
          ruleguard run tests/wazuh/suite.json
          --api https://wazuh-test.example.internal:55000
          --ca-file ci/manager-ca.pem
          --json candidate.json --junit candidate.xml --markdown candidate.md
      - name: Show the result on the pull request
        if: always()
        run: cat candidate.md >> "$GITHUB_STEP_SUMMARY"
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: ruleguard, path: "candidate.*" }
```

## 3. Compare against a saved baseline

Keep `baseline.json` from your current manager in the repository (or as an artifact from the main branch). On a pull request, run the suite and compare:

```yaml
      - run: ruleguard compare baseline.json candidate.json --json changes.json --html changes.html --markdown changes.md
      - if: always()
        run: cat changes.md >> "$GITHUB_STEP_SUMMARY"
```

The compare step exits with 1 when behavior changed, which fails the job until someone reviews the change. A changed rule ID is not automatically a regression, so read the summary before you decide.

## Things to keep in mind

- Reports leave out raw event text and tokens. Case names and rule metadata can still be sensitive, so think before you upload artifacts from a public repository.
- A failed request is never retried, because a retry could duplicate correlation events. Make sure the token lives long enough for the whole suite.
- Logtest does not prove log collection, indexing or alert delivery. Treat a green run as one signal.
