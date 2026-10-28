# Case study: typosquat-guard

A short write-up of why this project exists and what went into it, in STAR format.

## Situation

Typosquatting is one of the cheapest software supply-chain attacks. An attacker publishes a malicious package
one keystroke away from a popular one (for example `reqeusts` instead of `requests`) and waits for someone to
mistype it. PyPI regularly removes packages like these, and many of them steal credentials as soon as they're
installed. In code review, a one-character difference in `requirements.txt` is very easy to miss.

## Task

Catch these packages automatically, before they're merged. The tool had to be a lightweight check that fits into
the normal pull-request workflow, gives clear and actionable reports, can block a merge, and has no dependencies
of its own. A security tool with its own supply chain would defeat the purpose.

## Action

- Built **typosquat-guard** in pure Python with **zero runtime dependencies**.
- Implemented **five detection techniques**:
  - transposition-aware edit distance (optimal string alignment)
  - homoglyph substitution (`djang0` → `django`)
  - separator tricks (`beautiful-soup4`)
  - malicious affixes (`python-requests`)
  - numeric suffixes (`requests2`)
- Scaled the allowed edit distance with name length to keep false positives low on short names like `tox` / `nox`.
- Wrote a parser that handles real requirements files:
  - `-r` includes, with loop protection
  - extras
  - environment markers
  - inline comments
  - `pkg @ url`
- Normalized names per PEP 503 and reported each finding's exact `file:line` location.
- Bundled a ~130-package allowlist that teams can extend with their own internal package names.
- Shipped a CLI with text / Markdown / JSON output, CI-friendly exit codes (`--fail-on high|medium|low`) and
  optional Slack alerts.
- Packaged it as a **reusable GitHub Action**. It posts one PR comment, updates it on later pushes, and writes a job summary.
- Added 39 unit and CLI tests, ruff linting, and a CI matrix covering Python 3.9–3.13.

## Result

- Any repository can add a typosquat check to its pull requests with about 10 lines of YAML.
- Suspicious packages are flagged with a risk level, the legitimate package they imitate, and their exact location.
- The tool installs with `pip` and has no third-party dependencies.
- Legitimate plugin packages such as `pytest-cov`, `flask-login` and `django-cors-headers` aren't flagged.
- Turned an early, untested MVP into a documented, tested v0.2.0 with CI on five Python versions.

See the [README](../README.md) for usage, and [Limitations and roadmap](../README.md#limitations-and-roadmap) for what's next.
