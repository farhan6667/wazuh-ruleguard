# Changelog

## 0.2.0: 2026-10-09

- HTML reports are now readable pages (summary cards, a case table, before and after panels) instead of a JSON dump. Still one offline file with no scripts and a strict Content Security Policy.
- `--markdown` on `run` and `compare` writes a summary for CI, for example `$GITHUB_STEP_SUMMARY`.
- `ruleguard init` writes a starter suite and never overwrites a file. `ruleguard schema` prints a JSON Schema for suite files, also shipped as `ruleguard/suite.schema.json`.
- New CI guide in `docs/ci.md` with workflows for validation, a test manager run and a baseline comparison.
- Licence changed from MIT to Apache-2.0 for future versions, with a NOTICE file. Earlier commits stay under MIT.
- README redesigned with a banner, a how-it-works diagram and brand footer.

## 0.1.0: 2026-10-05: local prototype

Initial wazuh-ruleguard implementation, CLI, synthetic examples, documentation and unit tests.
Prepared for Python 3.10+. Local verification used Python 3.12 on Windows.
No public release or live engine compatibility certification has been completed.
