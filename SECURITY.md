# Security

This is an early prototype. Run against disposable or explicitly authorized test data.
Do not publish secrets or sensitive logs in issues or report artifacts.

## Reporting a problem

Report a vulnerability privately by email to nexaforge.services@gmail.com, with a synthetic
reproduction. Please do not open a public issue for it. There is no
guaranteed response time or paid bounty. Fixes go into the latest release only; older
versions are not patched separately.

## What the tool does and does not do with input

- Python reads supplied JSON and XML; it never executes input as code and never starts
  another program.
- Rule XML with a DOCTYPE or ENTITY declaration is refused, so entity expansion and external
  entities cannot be triggered through `ruleguard lint`.
- When `lint` scans a folder, a file that links outside that folder is refused.
- Suite and report JSON over 64 MiB and rule files over 4 MB are refused instead of read into
  memory. Malformed, deeply nested or wrongly typed input ends with a short error and exit
  code 2, not a traceback.
- The API token is read only from `WAZUH_API_TOKEN`, sent only to the HTTPS origin you name,
  with certificate checks on, proxies and redirects ignored.
- HTML reports escape untrusted content and do not load remote scripts or assets.

Reports are summaries, not proof that data is anonymized or that a detection policy is safe.
Review artifacts before sharing.

RuleGuard has no runtime dependencies. The build backend (setuptools) is bounded in
`pyproject.toml`, and CI actions are pinned to commit SHAs and updated through Dependabot.
