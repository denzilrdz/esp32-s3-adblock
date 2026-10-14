#!/usr/bin/env bash
# Formats all C/C++ (clang-format) and Python (black) sources in place.
#   tools/format.sh          # format
#   tools/format.sh --check  # CI: fail if anything would change
set -euo pipefail
cd "$(dirname "$0")/.."
CF=".venv/bin/clang-format"; [ -x "$CF" ] || CF="clang-format"
BLACK=".venv/bin/black"; [ -x "$BLACK" ] || BLACK="black"
mapfile_cpp() { git ls-files 'lib/core/**/*.cpp' 'lib/core/**/*.h' 'src/**/*.cpp' 'src/**/*.h' 'src/*.cpp' 'test/**/*.cpp' 'test/**/*.h' | grep -v 'src/secrets'; }
if [[ "${1:-}" == "--check" ]]; then
  mapfile_cpp | xargs "$CF" --dry-run --Werror
  "$BLACK" --check --quiet tools
else
  mapfile_cpp | xargs "$CF" -i
  "$BLACK" --quiet tools
fi
