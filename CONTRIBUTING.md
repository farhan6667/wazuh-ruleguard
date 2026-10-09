# Contributing to Wazuh RuleGuard

Thanks for wanting to help. This is a small, free project and it gets better when people who run Wazuh every day try it and tell us what is missing. You do not need to be an expert, and a good bug report counts as a real contribution.

## Ways to help

- **Try it on a real Wazuh and report what happened.** The project is a prototype and the demo data is synthetic, so live results are the most valuable thing you can send. Say your Wazuh version, your OS and Python version, the exact command and what you expected. Use the "Compatibility report" issue form.
- **Send a synthetic test case or example.** A suite for a log source you know (SSH, Windows logon, web server) with invented log lines, one case that must alert and one that must stay quiet.
- **Pick an issue.** Look for [good first issue](https://github.com/farhan6667/wazuh-ruleguard/labels/good%20first%20issue) and [help wanted](https://github.com/farhan6667/wazuh-ruleguard/labels/help%20wanted). Comment that you are taking it so two people do not do the same work.
- **Improve the docs.** If something confused you, fix the sentence that confused you.
- **Ask a question or share an idea** in [Discussions](https://github.com/farhan6667/wazuh-ruleguard/discussions). Not everything has to be an issue.

## Set up in two minutes

```sh
git clone https://github.com/farhan6667/wazuh-ruleguard.git
cd wazuh-ruleguard
python -m unittest discover -s tests -v
```

That is the whole setup. There are no runtime dependencies and no build step, and it needs Python 3.10 or newer. To try the CLI from the source tree, use `python -m ruleguard --help`.

## Rules that keep the project useful

1. **Never send real data.** No JWTs, passwords, hostnames, agent IDs, organization logs or real rule files. Invent log lines that follow the same shape. Reports from this tool can be sensitive too, so check one before you paste it.
2. **Keep runtime dependencies at zero** unless there is a clear, documented benefit for users. If you think there is, open an issue first.
3. **Add a test with every behaviour change**, and make it fail without your change. Tests use synthetic data and never touch the network.
4. **Keep reports safe.** HTML must stay one offline file with no scripts and no remote assets, and anything from an input file must be escaped.
5. **Say what you verified.** In the pull request, list what you ran and what you did not. "Not tested against a live manager" is a fine thing to write.
6. **Small pull requests get merged faster.** One idea per pull request, with the reason in the first sentence.

## Pull request checklist

- [ ] `python -m unittest discover -s tests -v` passes
- [ ] New behaviour has a test, and the CHANGELOG has a line under Unreleased
- [ ] The README or docs are updated if the command line changed
- [ ] No real logs, credentials or identifiers are in the diff

## Hacktoberfest

The repository carries the `hacktoberfest` topic. A pull request is welcome whether or not you take part in the event, and low-effort changes that only exist to count toward it will be closed politely.

## Be kind

Be patient with newcomers and with maintainers. Our [Code of Conduct](CODE_OF_CONDUCT.md) is short: be respectful, assume good intent and keep feedback about the work.

## Security problems

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).
