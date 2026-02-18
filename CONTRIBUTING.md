# Contributing

Contributions are welcome! Every little bit helps, and credit will always be given.

## Requirements

- Python 3.14+
- [uv](https://github.com/astral-sh/uv) package manager
- [prek](https://github.com/j178/prek) (pre-commit hook runner) — installed automatically by uv
- Windsurf IDE installed (needed to run surfmon)

Fork and clone the repository, then:

```bash
cd surfmon
uv sync
```

This installs all dependencies including dev tools. If `uv` is not installed, see the [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/).

Run the CLI with `uv run surfmon [ARGS...]`.

## Tasks

This project uses [poethepoet](https://github.com/nat-n/poethepoet) as a task runner. Run `poe` to list all available tasks. Key tasks:

- `poe check` — lint + type check (parallel)
- `poe fix` — auto-fix lint issues and format
- `poe test` — run tests (excluding slow)
- `poe test-all` — run all tests including slow

- `poe docs` — serve documentation locally

## Development

1. Create a branch: `git switch -c feature-or-bugfix-name`
2. Make your changes
3. Commit — git hooks automatically run formatting, linting, and tests

Don't worry about the changelog — it is generated automatically from commit messages.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/). A git hook enforces the format, so you'll get immediate feedback if the message doesn't match:

```
<type>[(scope)]: Subject
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `ci`, `chore`, `perf`.

## Pull requests

Link to any related issue in the PR description. Keep commits focused — one logical change per commit. We squash-merge PRs, so don't worry about a clean commit history within the PR.
