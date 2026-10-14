#!/usr/bin/env bash
# Runs the native tests with coverage instrumentation and writes an HTML report to
# coverage/index.html plus a summary on stdout. Only lib/core is measured.
#   tools/coverage.sh            # all tests
#   tools/coverage.sh -f test_dns
set -euo pipefail
cd "$(dirname "$0")/.."
GCOVR=".venv/bin/gcovr"
[ -x "$GCOVR" ] || GCOVR="gcovr"
rm -rf coverage .pio/build/coverage
pio test -e coverage "$@"
# Apple clang writes LLVM-format .gcda files: read them with llvm-cov's gcov mode.
if [[ "$(uname)" == "Darwin" ]]; then GCOV=(--gcov-executable "xcrun llvm-cov gcov"); else GCOV=(); fi
mkdir -p coverage
"$GCOVR" "${GCOV[@]}" --root . --filter 'lib/core/' --object-directory .pio/build/coverage \
  --html-details coverage/index.html --xml coverage/coverage.xml --print-summary --sort uncovered-percent
echo "HTML report: coverage/index.html"
