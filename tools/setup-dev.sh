#!/usr/bin/env bash
# Creates .venv with the pinned developer tools and installs the git pre-commit hook.
# Nothing is installed globally; delete .venv to remove everything.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements-dev.txt
.venv/bin/pre-commit install
echo "Dev tools ready in .venv (clang-format, black, gcovr, pre-commit); pre-commit hook installed."
