# Changelog

## v0.2.0 (2026-10-28)

First public release of **typosquat-guard**. It catches typosquatted and look-alike Python packages before they reach your supply chain.

### Highlights
- **5 detection techniques**: transposition-aware edit distance, homoglyphs (`djang0`), separator tricks (`beautiful-soup4`), affixes (`python-requests`) and numeric suffixes (`requests2`)
- **Risk scoring** (HIGH / MEDIUM / LOW) with the exact `file:line` of each finding
- **Real requirements parsing**: `-r` includes, extras, environment markers, inline comments, `pkg @ url`
- **Bundled allowlist** of ~130 popular PyPI packages, which you can extend with your own
- **CLI** with text / Markdown / JSON output and `--fail-on` exit codes for CI
- **Reusable GitHub Action** that keeps a single PR comment up to date and writes a job summary
- Optional **Slack** alerts
- **Zero runtime dependencies**. Tested on Python 3.9–3.13.

### Install
```bash
pip install git+https://github.com/sxxsalihxxs/pypi-typosquat-guard.git@v0.2.0
typosquat-guard requirements.txt
```

### GitHub Action
```yaml
- uses: sxxsalihxxs/pypi-typosquat-guard@v0.2.0
  with:
    files: requirements.txt
    fail-on: high
```

## v0.1.0

Initial MVP.
