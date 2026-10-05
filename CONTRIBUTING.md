# Contributing

Run `python -m unittest discover -s tests -v` before submitting changes.
Report the Python version, OS, exact command, expected outcome and sanitized evidence.
Use synthetic data wherever possible. Never include JWTs, passwords, organization raw logs
or production host identifiers. Discuss new formats or adapters before large changes.
Keep runtime dependencies empty unless there is a clear, documented user benefit.

The examples and automated CI tests are synthetic. Report real compatibility results with
the Wazuh version and environment so that synthetic demos are not mistaken for validation.
Contributions should solve reproducible user problems; cosmetic activity is not a goal.
