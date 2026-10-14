---
name: release
description: Cut a release. Use when bumping the firmware version, updating CHANGELOG.md, creating a signed version tag, or checking what the release GitHub Actions workflow builds and publishes.
disable-model-invocation: true
---

# Release

Semantic versioning: MAJOR (breaking config/format/partition change), MINOR
(features), PATCH (fixes).

## Steps

1. Make sure `main` is green: `pio test -e native` and `pio run -e esp32s3 -e c3 -e esp32dev`.
2. Bump the version in **one place**: `FW_VERSION` in `platformio.ini`
   (`-DFW_VERSION=\"X.Y.Z\"` in `[env]` build_flags). It shows on the dashboard,
   in `/api/stats` and in the boot log.
3. `CHANGELOG.md` (Keep a Changelog):
   - move `## [Unreleased]` items under `## [X.Y.Z] - YYYY-MM-DD`;
   - add an empty Unreleased section;
   - update the compare links at the bottom.
4. If the partition table or blocklist format changed: say so under **Changed**
   with "requires USB flash" / "requires new blocklist", and bump MAJOR.
5. Commit: `chore(release): vX.Y.Z` (signed).
6. Tag (signed, annotated): `git tag -s vX.Y.Z -m "vX.Y.Z"`, then verify with
   `git tag -v vX.Y.Z`.
7. **Ask the user before pushing**: `git push origin main` and
   `git push origin vX.Y.Z`.

## What CI does on a `v*` tag (`.github/workflows/release.yml`)

- Builds `esp32s3`, `c3` and `esp32dev` with the placeholder `secrets.h`.
- Attaches to a GitHub Release: `firmware-<env>-vX.Y.Z.bin`, `bootloader.bin`,
  `partitions.bin`, a merged `factory-esp32s3-vX.Y.Z.bin` (for a first flash at
  0x0), `SHA256SUMS`, and `.sig` files if the signing secret is configured.
- Release notes are taken from the matching CHANGELOG section.

## Signed firmware (optional)

```bash
python3 tools/sign_firmware.py --key ~/keys/adblock-fw.pem \
  .pio/build/esp32s3/firmware.bin firmware.signed.bin
```

The private key never goes in the repo. In CI it comes from the `FW_SIGNING_KEY`
secret. The device only enforces signatures if `FW_PUBKEY_PEM` is set in
`secrets.h`.
