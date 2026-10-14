## What and why

<!-- What does this change, and why? Link issues with "Fixes #123". -->

## How it was tested

- [ ] `pio test -e native` passes (new/changed behaviour has tests)
- [ ] `tools/format.sh --check` and `tools/lint.sh` are clean
- [ ] Firmware builds (`pio run -e esp32s3`; CI builds all boards)
- [ ] Tested on hardware: <!-- board + what you checked, or "not tested on hardware" -->

## Checklist

- [ ] Conventional Commit messages
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Docs/`CLAUDE.md`/skills updated if commands, behaviour or files changed
- [ ] Security checklist done if this touches the dashboard, OTA, config or network parsing
- [ ] No secrets (`src/secrets.h`, passwords, tokens) in the diff
