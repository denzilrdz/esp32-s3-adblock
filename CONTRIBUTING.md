# Contributing

Thanks for helping! Bug reports, blocklist ideas and pull requests are welcome.

## Getting started

```bash
git clone https://github.com/denzilrdz/esp32-s3-adblock && cd esp32-s3-adblock
tools/setup-dev.sh            # pinned tools into .venv (uv) + git hooks
cp src/secrets.example.h src/secrets.h
.venv/bin/pio test -e native  # unit tests, no hardware needed
.venv/bin/pio run -e esp32s3  # firmware build
```

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing core logic or tasks.
[CLAUDE.md](CLAUDE.md) has the short version of the commands and rules.

## Rules

- **Tests:** every feature or bug fix comes with native tests in `test/`
  (`pio test -e native`). Core logic lives in `lib/core` behind interfaces so it runs
  on your computer; ESP32-only glue lives in `src/`.
- **DNS hot path:** no heap allocation, no blocking calls, no flash writes.
- **Style:** `tools/format.sh` (clang-format + black) and `tools/lint.sh`
  (clang-tidy) must be clean; the hooks run them for you.
- **Commits:** small, focused, [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`), ideally signed.
- **Secrets:** never commit `src/secrets.h`, passwords, keys or tokens.
- **Security-sensitive changes** (dashboard, OTA, anything parsing network input):
  go through `.claude/skills/security-checklist/SKILL.md`.
- **Changelog:** add a line under `## [Unreleased]` in `CHANGELOG.md`.

## Pull requests

CI must pass (format, lint, tests, all three firmware builds). Describe what you
tested; if you tested on hardware, say which board.

By contributing you agree that your contributions are licensed under the MIT License,
and you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
