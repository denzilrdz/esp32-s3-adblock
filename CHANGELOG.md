# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- CI: native tests failed on Linux GCC, which predefines `unix` as a macro; coverage
  failed because `pio` was only installed in `.venv`.

### Security
- GitHub Actions hardening: workflows audited with zizmor (auditor persona) and
  actionlint in CI and pre-commit; checkout credentials not persisted; per-job
  least-privilege permissions; job timeouts; no template expansion in scripts;
  release builds never use caches; Sigstore build-provenance attestations for
  release binaries; Dependabot cooldown; CODEOWNERS for CI and security-relevant
  paths.

## [0.1.0] - 2026-10-14

First release of the ESP32-S3 fork of
[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock).

### Added
- ESP32-S3 N16R8 target (`esp32s3`): octal PSRAM, 16 MB flash with two 4 MB OTA
  slots, ~7.9 MB LittleFS and a core-dump partition.
- Encrypted upstream DNS: DNS-over-TLS to Cloudflare and Quad9 by hard-coded IP with
  certificate verification, TLS session resumption, DNS-over-HTTPS fallback, and
  plain DNS only when every encrypted upstream is down (configurable, logged).
- Health-tracked fallback chain with backoff, hedging after 1.2 s and SERVFAIL at
  2.5 s; pipelined DoT; EDNS padding; DNSSEC AD-flag pass-through.
- PSRAM response cache (TTL-aware, LRU, negative caching).
- Blocklist format v2: 48-bit hashes in a bucketed index held in PSRAM, custom
  block and allow rules, parent-domain matching.
- Daily blocklist update at 02:00 IST with ETag, streaming validation, atomic swap
  and boot recovery; retries hourly on failure.
- Dedicated FreeRTOS tasks for UDP/53, TCP/53, upstream, web and maintenance, all on
  the task watchdog; app rollback for unhealthy OTA firmware.
- Local answers for localhost, private reverse zones, `.local` and the Firefox DoH
  canary; optional iCloud Private Relay opt-out.
- Settings in NVS, editable on a new dashboard; hashed dashboard password with a
  serial-console setup code, login lockout, Host/Origin checks, POST-only API.
- Browser installer for the ESP32-S3 (GitHub Pages), release workflow, native unit tests with
  sanitizers and coverage, clang-format/clang-tidy, uv-managed tooling, git hooks.
- Documentation: architecture, router/IPv6 setup guide, Claude Code skills.

### Changed
- Blocking replies: AAAA returns `::`, HTTPS/SVCB return NODATA with an SOA, and
  EDNS clients get Extended DNS Error 15.
- Blocklist builder writes format v2 only; `www.` is no longer stripped.

### Fixed (compared with upstream)
- A failed or corrupt blocklist download no longer leaves the device without a list.
- Large blocklists no longer miss entries in crowded index buckets.
- A slow upstream no longer stalls every other query, the dashboard and OTA.
- Blocklist downloads verify HTTPS certificates and refuse redirects to plain HTTP.

### Removed
- ESP32-C3 and classic ESP32 support (this fork is ESP32-S3 only: PSRAM and 16 MB
  flash are required), upstream's 40-bit blocklist format, the Japanese README,
  the C3 web-installer binaries and the C3 SuperMini enclosure.

[Unreleased]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/denzilrdz/esp32-s3-adblock/releases/tag/v0.1.0
