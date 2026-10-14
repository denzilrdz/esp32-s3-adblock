#!/usr/bin/env bash
# Creates .venv with the pinned developer tools (pyproject.toml / uv.lock) and installs
# the git pre-commit and pre-push hooks. Nothing is installed globally; delete .venv
# to remove everything. Prefers uv (https://docs.astral.sh/uv/); falls back to pip.
set -euo pipefail
cd "$(dirname "$0")/.."
if command -v uv >/dev/null 2>&1; then
  uv sync --locked
else
  echo "uv not found: using python3 -m venv + pip (install uv for faster, locked installs)"
  python3 -m venv .venv
  .venv/bin/pip install -q --upgrade "pip>=25.1"
  .venv/bin/pip install -q --group dev
fi
.venv/bin/pre-commit install --hook-type pre-commit --hook-type pre-push
echo "Ready: .venv has clang-format, clang-tidy, black, gcovr, pre-commit, platformio; hooks installed."
