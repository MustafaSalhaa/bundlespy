# Contributing to BundleSpy

Thanks for your interest. Here is how to contribute without breaking things.

## What's welcome

- New detection rules in `rules/secrets.yaml`
- Bug fixes with a test that reproduces the issue
- False positive improvements
- Documentation fixes
- New report formats
- Performance improvements that don't weaken safety checks

## What's not welcome

- Changes that weaken network safety checks (IP blocking, scope enforcement, SSRF protection)
- Features that validate discovered credentials against external services
- Features that exploit discovered endpoints
- Telemetry or analytics of any kind

## Adding a detection rule

Edit `rules/secrets.yaml`. Each rule needs a unique ID, a tested regex pattern, severity,
confidence, description, remediation, and false positive notes.

Test it before submitting:

```bash
pytest tests/unit/ -v
```

If the rule has a high false positive rate, lower the confidence score and document it in fp_notes.

## Running tests

```bash
pip install pytest
pytest tests/unit/ -v
```

## Code style

- Type hints on function signatures
- Short functions with a clear single purpose
- Comments explain why, not what
- No print statements in library code - use logging
- Never log secrets, tokens, or credentials

## Pull requests

- One logical change per PR
- Tests for any new behavior
- Update README if you add a feature
- Keep commit messages short and descriptive
