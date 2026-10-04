# Contributing

Use Python 3.12+ with Hatch and uv installed. Clone `mountainash-settings` beside
this checkout, following the [installation instructions](README.md#installation).
The local Hatch environments select that sibling through `requirements-hatch.txt`
and the dependencies in `hatch.toml`.

## Branches and checks

Branch from `develop` using `feature/*`, `bugfix/*` or a focused documentation
branch. Open PRs against `develop`; release branches promote reviewed changes to
`main`.

From the repository root:

```bash
hatch run test:test
hatch run ruff:ruff check src tests tools examples
hatch run mypy:check
git diff --check
```

For recipe changes, run the standalone consumer checks first:

```bash
hatch run test:test-quick tests/examples -q
```

Each recipe lives in `examples/<topic>/` with `example.py` and `README.md`. Keep
it independently runnable, use synthetic credentials, assert the demonstrated
behavior, and document its expected output. Link it from `examples/README.md`.
Tests run each copied recipe in its own process from a different working
directory, and execute the root README quick start separately.

See [installed typing](docs/typing.md) for artifact qualification on Python
3.12/3.13, [AGENTS.md](AGENTS.md) for repository conventions, and
[RELEASE.md](RELEASE.md) for release operations.
