#!/usr/bin/env bash
# Verify that a copier-uv-bleeding scaffold meets all quality expectations.
# Run from the project root: bash scripts/verify-scaffold.sh
# Exit code 0 = all checks pass, non-zero = failures found.

set -euo pipefail

passed=0
failed=0
warnings=0

pass() { printf "  ✅ %s\n" "$1"; passed=$((passed + 1)); }
fail() { printf "  ❌ %s\n" "$1"; failed=$((failed + 1)); }
warn() { printf "  ⚠️  %s\n" "$1"; warnings=$((warnings + 1)); }

section() { printf "\n━━━ %s ━━━\n" "$1"; }

# ---------------------------------------------------------------------------
section "Project Structure"
# ---------------------------------------------------------------------------

# Core files
for f in pyproject.toml README.md README_TEMPLATE.md LICENSE CHANGELOG.md CONTRIBUTING.md \
         CODE_OF_CONDUCT.md SECURITY.md .gitignore .envrc .env.example \
         .copier-answers.yml prek.toml .editorconfig \
         .markdownlint.yaml .lychee.toml mkdocs.yml; do
    if [[ -f "$f" ]]; then pass "$f exists"; else fail "$f missing"; fi
done

# Source package marker (__init__.py required for editable installs)
if compgen -G "src/*/__init__.py" > /dev/null 2>&1; then
    pass "src/*/__init__.py exists"
else
    fail "src/*/__init__.py missing (required for uv sync / editable installs)"
fi

# Read copier answers for conditional checks
repo_provider=$(grep 'repository_provider' .copier-answers.yml 2>/dev/null | sed 's/.*: *//' || echo "github.com")

# Docs
for f in docs/index.md docs/changelog.md docs/contributing.md docs/license.md \
         docs/code_of_conduct.md docs/reference/api.md; do
    if [[ -f "$f" ]]; then pass "$f exists"; else fail "$f missing"; fi
done

# Provider-specific files
if [[ "$repo_provider" == "github.com" ]]; then
    for f in .github/workflows/ci.yml .github/workflows/release.yml \
             .github/workflows/copier-update.yml .github/dependabot.yml \
             .github/FUNDING.yml .github/actionlint.yaml; do
        if [[ -f "$f" ]]; then pass "$f exists"; else fail "$f missing"; fi
    done
    if [[ -d ".github/ISSUE_TEMPLATE" ]]; then pass "Issue templates dir exists"; else fail "Issue templates missing"; fi
    if [[ -f ".github/pull_request_template.md" ]]; then pass "PR template exists"; else fail "PR template missing"; fi
elif [[ "$repo_provider" == "gitlab.com" ]]; then
    if [[ -f ".gitlab-ci.yml" ]]; then pass ".gitlab-ci.yml exists"; else fail ".gitlab-ci.yml missing"; fi
fi

# ---------------------------------------------------------------------------
section "Security"
# ---------------------------------------------------------------------------

if grep -q '^\.env$' .gitignore; then
    pass ".env is gitignored"
else
    fail ".env is NOT in .gitignore — secrets at risk"
fi

if grep -q '!\.env\.example' .gitignore; then
    pass ".env.example is excluded from gitignore"
else
    fail ".env.example not excluded — it should be tracked"
fi

if grep -q 'detect-private-key' prek.toml; then
    pass "detect-private-key hook present"
else
    fail "detect-private-key hook missing"
fi

# Drift check: env vars used by template scripts must be documented
# shellcheck disable=SC2043  # single-item loop — ready for more vars
for var in COPIER_CHECK_INTERVAL; do
    if grep -q "$var" .envrc 2>/dev/null; then
        pass "$var documented in .envrc"
    else
        fail "$var used by template scripts but not documented in .envrc"
    fi
    if grep -q "$var" .env.example 2>/dev/null; then
        pass "$var documented in .env.example"
    else
        fail "$var used by template scripts but not documented in .env.example"
    fi
done

if grep -q 'gitleaks' prek.toml; then
    pass "gitleaks hook present"
else
    fail "gitleaks hook missing"
fi

if [[ -f "SECURITY.md" ]]; then
    pass "SECURITY.md exists"
else
    fail "SECURITY.md missing — no vulnerability reporting policy"
fi

# ---------------------------------------------------------------------------
section "Python / uv Configuration"
# ---------------------------------------------------------------------------

if grep -q 'requires-python.*3\.14' pyproject.toml; then
    pass "requires-python >= 3.14"
else
    warn "requires-python is not 3.14+"
fi

if grep -q 'uv_build' pyproject.toml; then
    pass "uv_build backend configured"
else
    fail "build backend is not uv_build"
fi

if grep -q 'default-groups' pyproject.toml; then
    pass "dependency groups configured"
else
    fail "No dependency groups found"
fi

if [[ -f "uv.lock" ]]; then pass "uv.lock exists"; else warn "uv.lock missing — run uv sync"; fi
if [[ -d ".venv" ]]; then pass ".venv exists"; else warn ".venv missing — run uv sync"; fi

# ---------------------------------------------------------------------------
section "Ruff Linting"
# ---------------------------------------------------------------------------

for rule in '"E"' '"F"' '"UP"' '"I"' '"B"' '"SIM"' '"S"' '"T20"' '"PT"' '"PERF"'; do
    if grep -q "$rule" pyproject.toml; then
        pass "Ruff rule $rule enabled"
    else
        fail "Ruff rule $rule not found"
    fi
done

if grep -q 'per-file-ignores' pyproject.toml && grep -q '"S101"' pyproject.toml; then
    pass "S101 (assert) allowed in tests"
else
    fail "S101 not exempted for tests"
fi

# ---------------------------------------------------------------------------
section "Testing"
# ---------------------------------------------------------------------------

if grep -q 'pytest' pyproject.toml; then pass "pytest configured"; else fail "pytest not found"; fi
if grep -q 'pytest-cov' pyproject.toml; then pass "pytest-cov configured"; else fail "pytest-cov not found"; fi
if grep -q 'pytest-randomly' pyproject.toml; then pass "pytest-randomly configured"; else fail "pytest-randomly not found"; fi

if grep -q 'branch = true' pyproject.toml; then
    pass "Branch coverage enabled"
else
    fail "Branch coverage not enabled"
fi

# ---------------------------------------------------------------------------
section "Type Checking"
# ---------------------------------------------------------------------------

if grep -q 'ty' pyproject.toml; then pass "ty type checker configured"; else fail "ty not found"; fi
if grep -q 'python-version.*3\.14' pyproject.toml; then pass "ty targets Python 3.14"; else warn "ty python version mismatch"; fi

# ---------------------------------------------------------------------------
section "Pre-commit Hooks"
# ---------------------------------------------------------------------------

for hook in trailing-whitespace end-of-file-fixer check-yaml check-toml \
            check-json check-added-large-files check-merge-conflict \
            mixed-line-ending detect-private-key gitleaks ruff ruff-format \
            uv-lock shellcheck typos markdownlint \
            conventional-pre-commit; do
    if grep -q "$hook" prek.toml; then
        pass "Hook: $hook"
    else
        fail "Hook missing: $hook"
    fi
done

# GitHub-only hooks
if [[ "$repo_provider" == "github.com" ]]; then
    if grep -q 'actionlint' prek.toml; then
        pass "Hook: actionlint"
    else
        fail "Hook missing: actionlint"
    fi
fi

# Local hooks
if grep -q 'ty check' prek.toml; then
    pass "Local hook: ty type checker"
else
    fail "Local hook missing: ty"
fi

if grep -q 'pytest.*cov-fail-under' prek.toml; then
    pass "Local hook: pytest with coverage gate"
else
    fail "Local hook missing: pytest coverage gate"
fi

# ---------------------------------------------------------------------------
section "CI Workflows"
# ---------------------------------------------------------------------------

ci=".github/workflows/ci.yml"
if [ -f "$ci" ]; then
    if grep -q 'ubuntu' "$ci" && grep -q 'macos' "$ci" && grep -q 'windows' "$ci"; then
        pass "CI: multi-OS matrix (Linux, macOS, Windows)"
    else
        fail "CI: missing OS variants in matrix"
    fi

    if grep -q 'lowest-direct' "$ci"; then
        pass "CI: resolution testing (highest + lowest-direct)"
    else
        fail "CI: no resolution testing"
    fi

    if grep -q 'concurrency' "$ci"; then
        pass "CI: concurrency group configured"
    else
        warn "CI: no concurrency group"
    fi

    if grep -qi 'codecov\|coveralls\|coverage' "$ci"; then
        pass "CI: coverage upload configured"
    else
        fail "CI: no coverage upload (Codecov/Coveralls) — coverage data goes nowhere"
    fi
elif [ -f ".gitlab-ci.yml" ]; then
    pass "CI: GitLab CI configured"
else
    warn "CI: no CI workflow found"
fi

prd=".github/workflows/pr-description.yml"
if [ -f "$prd" ]; then
    pass "PR description check workflow present"
elif [ -d ".github" ]; then
    warn "PR description check workflow missing"
fi

rel=".github/workflows/release.yml"
if [ -f "$rel" ]; then
    if grep -q 'semantic-release' "$rel"; then
        pass "Release: semantic-release configured"
    else
        fail "Release: semantic-release not found"
    fi

    if grep -q 'uv publish' "$rel"; then
        pass "Release: PyPI publishing configured"
    else
        warn "Release: no PyPI publishing step"
    fi
fi

# ---------------------------------------------------------------------------
section "Documentation"
# ---------------------------------------------------------------------------

if grep -q 'name: material' mkdocs.yml; then pass "MkDocs Material theme"; else fail "Not using Material theme"; fi
if grep -q 'mkdocstrings' mkdocs.yml; then pass "mkdocstrings configured"; else fail "mkdocstrings missing"; fi
if grep -q 'llmstxt' mkdocs.yml; then pass "llms.txt plugin enabled"; else warn "llms.txt plugin missing"; fi
if grep -q 'git-revision-date' mkdocs.yml; then pass "Git revision date plugin"; else warn "Git revision date plugin missing"; fi

# ---------------------------------------------------------------------------
section "Poe Tasks"
# ---------------------------------------------------------------------------

for task in setup lint format typecheck test test-affected test-all test-cov check fix \
            docs docs-build prek check-template update-template; do
    if grep -q "^$task " pyproject.toml || grep -q "^$task = " pyproject.toml || grep -q "^$task\." pyproject.toml || grep -q "\[tool\.poe\.tasks\.$task\]" pyproject.toml; then
        pass "Poe task: $task"
    else
        fail "Poe task missing: $task"
    fi
done

# ---------------------------------------------------------------------------
section "README Quality"
# ---------------------------------------------------------------------------

if grep -q '\[!\[ci\]' README.md; then pass "CI badge present"; else warn "CI badge missing"; fi
if grep -q '\[!\[release\]' README.md; then pass "Release badge present"; else warn "Release badge missing"; fi
if grep -q '\[!\[documentation\]' README.md; then pass "Docs badge present"; else warn "Docs badge missing"; fi
if grep -qi 'codecov\|coveralls\|coverage.*badge\|coverage.*img' README.md; then pass "Coverage badge present"; else warn "Coverage badge missing"; fi

# Check for the known README formatting bug (#83)
if grep -q '```##' README_TEMPLATE.md; then
    fail "README_TEMPLATE: code fence merged with heading (no blank line) — copier-uv-bleeding#83"
else
    pass "README_TEMPLATE: no code fence / heading collision"
fi

# ---------------------------------------------------------------------------
section "CONTRIBUTING.md Consistency"
# ---------------------------------------------------------------------------

if grep -q 'make setup' CONTRIBUTING.md; then
    fail "CONTRIBUTING.md still references 'make setup' (no Makefile)"
else
    pass "CONTRIBUTING.md does not reference 'make setup'"
fi

if grep -q 'uv sync\|uv run' CONTRIBUTING.md; then
    pass "CONTRIBUTING.md references uv commands"
else
    fail "CONTRIBUTING.md missing uv commands"
fi

# ---------------------------------------------------------------------------
section "Markdown Lint"
# ---------------------------------------------------------------------------

if command -v markdownlint &>/dev/null; then
    md_errors=$(markdownlint README.md README_TEMPLATE.md CONTRIBUTING.md CHANGELOG.md 2>&1 || true)
    if [[ -z "$md_errors" ]]; then
        pass "Core .md files pass markdownlint"
    else
        fail "Markdownlint errors found:"
        echo "$md_errors" | head -20 | sed 's/^/       /'
    fi
else
    warn "markdownlint not installed — skipping"
fi

# ---------------------------------------------------------------------------
section "Ruff Check (quick)"
# ---------------------------------------------------------------------------

if command -v ruff &>/dev/null || [[ -f ".venv/bin/ruff" ]]; then
    ruff_bin="${VIRTUAL_ENV:-$PWD/.venv}/bin/ruff"
    if [[ ! -x "$ruff_bin" ]]; then ruff_bin="ruff"; fi
    if "$ruff_bin" check src &>/dev/null; then
        pass "ruff check passes on src/"
    else
        ruff_errors=$("$ruff_bin" check src 2>&1 || true)
        fail "ruff errors found:"
        echo "$ruff_errors" | head -20 | sed 's/^/       /'
    fi
else
    warn "ruff not available — skipping"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

printf "\n━━━ Summary ━━━\n"
printf "  ✅ Passed:   %d\n" "$passed"
printf "  ❌ Failed:   %d\n" "$failed"
printf "  ⚠️  Warnings: %d\n" "$warnings"
echo ""

if ((failed > 0)); then
    printf "🔴 %d check(s) failed.\n" "$failed"
    exit 1
else
    printf "🟢 All checks passed"
    if ((warnings > 0)); then printf " (%d warnings)" "$warnings"; fi
    printf ".\n"
    exit 0
fi
