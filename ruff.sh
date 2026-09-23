#!/usr/bin/env bash
# Lint + format check with ruff — mirrors the CI (.github/workflows/ruff.yaml).
# Run from the repo root:  bash ruff.sh
#
# To auto-fix instead of just checking:
#   ruff check --fix .     # fix lint issues
#   ruff format .          # apply formatting
set -euo pipefail

if ! command -v ruff >/dev/null 2>&1; then
    echo "ruff not found — install it with:  pip install ruff" >&2
    exit 1
fi

echo "== ruff check =="
ruff check .

echo "== ruff format --check =="
ruff format --check .

echo "All ruff checks passed."
