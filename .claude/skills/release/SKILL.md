---
name: release
description: Cut a release. Use when bumping the firmware version, updating CHANGELOG.md, creating a signed version tag, or checking what the release GitHub Actions workflow builds and publishes (binaries, SHA256SUMS, web installer).
disable-model-invocation: true
---

# Release

Semantic versioning: MAJOR (breaking: partition table, blocklist format, settings
schema), MINOR (features), PATCH (fixes).

## Steps

1. `main` is green locally: `pio test -e native`, `tools/lint.sh`,
   `tools/format.sh --check`, and `pio run -e esp32s3`.
2. Bump `FW_VERSION` in `platformio.ini` (`[esp32_base]` build_flags,
   `-DFW_VERSION=\"X.Y.Z\"`). It shows in the boot log, `/api/stats` and the dashboard.
   The release workflow fails if the tag and `FW_VERSION` differ.
3. `CHANGELOG.md` (Keep a Changelog): move `[Unreleased]` items under
   `## [X.Y.Z] - YYYY-MM-DD`, leave an empty `[Unreleased]`, update the compare links
   at the bottom. The workflow uses this section as the release notes (it fails if
   the section is missing).
4. Partition table / blocklist format / settings schema changed? Say so under
   **Changed** ("requires USB flash", "requires a new blocklist") and bump MAJOR.
5. Commit: `chore(release): vX.Y.Z` (signed).
6. Tag (signed, annotated): `git tag -s vX.Y.Z -m "vX.Y.Z"`; check with
   `git tag -v vX.Y.Z`.
7. **Ask the user before pushing**: `git push origin main` then `git push origin vX.Y.Z`.

## What `.github/workflows/release.yml` does on a `v*` tag

- Builds `esp32s3` (tools from `uv.lock`, placeholder `secrets.h`).
- Attaches `firmware-esp32s3-vX.Y.Z.bin`, `factory-esp32s3-vX.Y.Z.bin` (flash at 0x0),
  `firmware-esp32s3-vX.Y.Z.elf` (for crash decoding) and `SHA256SUMS` to the release.
- Creates Sigstore build-provenance attestations for every `.bin`. Users verify a
  download with `gh attestation verify factory-esp32s3-vX.Y.Z.bin -R denzilrdz/esp32-s3-adblock`.
- Uses no caches (a poisoned cache can't reach release artifacts) and never cancels
  an in-progress release.
- Deploys the browser installer to GitHub Pages: `installer/index.html` +
  `manifest.json` (ESP32-S3) + esp-web-tools vendored from the npm tarball
  pinned in `installer/esp-web-tools.lock` (SHA-512 checked). Needs Pages set to
  "GitHub Actions" in the repo settings.

Firmware images are not signed yet (ARCHITECTURE.md §15).
