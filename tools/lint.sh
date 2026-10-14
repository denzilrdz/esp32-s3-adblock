#!/usr/bin/env bash
# clang-tidy over the portable core (lib/core) using .clang-tidy. Exits non-zero on
# findings. Uses the pinned clang-tidy from .venv (tools/setup-dev.sh) if present.
set -euo pipefail
cd "$(dirname "$0")/.."
TIDY=".venv/bin/clang-tidy"; [ -x "$TIDY" ] || TIDY="clang-tidy"
EXTRA=()
if [[ "$(uname)" == "Darwin" ]]; then EXTRA=(-isysroot "$(xcrun --show-sdk-path)"); fi
status=0
for f in $(git ls-files 'lib/core/**/*.cpp'); do
  "$TIDY" --quiet --config-file=.clang-tidy "$f" -- -std=gnu++17 -Ilib/core "${EXTRA[@]}" || status=1
done
exit $status
