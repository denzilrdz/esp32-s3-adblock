# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.7] - 2026-10-23

Fixes the board restarting on its own, and the dashboard now explains restarts.
Update from the dashboard (_Device → Check for updates_); settings and bans are kept.

### Added

- _Device → Health_ shows why the board last restarted: power on, a power dip, a crash
  or watchdog, or the firmware's own reason (for example "Wi-Fi down for 10 min",
  "firmware update" or the Reboot button). After a crash it also shows the crash
  record (the task, the reason and a backtrace for decoding), even one from before
  this update, so a restart can be explained without a USB cable.

### Fixed

- The board could restart on its own (a watchdog reset) when a phone or laptop sent a
  dashboard request slowly, for example when its Wi-Fi hiccuped mid-request: the web
  server busy-waited and starved the system for more than 5 s. One slow device on the
  network was enough, without a password. The dashboard now runs at the lowest
  priority and can't reset the board.
- The daily blocklist download could also restart the board when connecting to
  GitHub took more than 5 s (a slow DNS lookup, connection or handshake around 03:00).
- A slow encrypted handshake with the DNS provider no longer risks a watchdog reset.
- A DNS-over-TLS answer larger than 4 KB is skipped instead of closing the encrypted
  connection and failing every other lookup on it.

## [0.2.6] - 2026-10-23

The dashboard now asks for a password before showing anything. Update from the
dashboard (_Device → Check for updates_); settings and bans are kept. After the
update, reload the dashboard tab once to get the login screen.

### Security

- The dashboard now opens on a login screen. Before, anyone on your network could see
  the statistics, connected devices and settings without a password (only changes
  needed one). You stay logged in while the page is open (up to 24 h, or 30 min after
  closing it), there is a _Log out_ button, and changing the password logs out every
  browser. Scripts can keep using Basic Auth.

## [0.2.5] - 2026-10-22

A DNS reliability fix for power cuts. Update from the dashboard (_Device → Check for
updates_); settings and bans are kept.

### Fixed

- DNS could stay slow or stop answering after a power cut until the board was
  restarted. The internet is slow for a while after the router comes back, and every
  slow answer counted as a failure, so working DNS providers were marked down one
  after another and the board could open an encrypted connection to each of them,
  enough to run out of memory. It now keeps at most two encrypted connections open,
  and a provider that is still answering is no longer marked down for being slow.
- The dashboard's _Free heap_ line also shows the largest free memory block, and a
  failed encrypted connection is logged with its error code.

## [0.2.4] - 2026-10-21

A Wi-Fi reliability fix. Update from the dashboard (_Device → Check for updates_);
settings and bans are kept.

### Changed

- A board that has joined its Wi-Fi before no longer opens the setup network when that
  network is missing at boot (e.g. the router is still starting after a power cut). It
  retries every 5 seconds until the network is back. The setup network still opens for
  new or mistyped credentials, and for a known network that keeps rejecting the
  password.

## [0.2.3] - 2026-10-18

A Wi-Fi setup fix. Update from the dashboard (_Device → Check for updates_);
settings and bans are kept.

### Fixed

- After a failed Wi-Fi join (e.g. a wrong password) the setup page showed no networks,
  only "Other network", so the name had to be typed by hand: the scan ran while the
  board was still retrying the saved network. It now stops that first, so the list is
  always filled, and the page offers "Re-enter the password for `<network>`" in one tap.

## [0.2.2] - 2026-10-18

Fixes for bans and for Wi-Fi setup. Update from the dashboard (_Device → Check for
updates_); settings and bans are kept.

### Fixed

- A banned device could be silently unbanned: after a restart, changing any ban
  rewrote the list from the devices seen since boot, dropping banned devices that were
  offline. The ban list is now kept on its own and only changes when you ban or unban.
- A ban didn't apply once the board had seen 96 devices (the client table was full),
  and banning a device that wasn't in the table answered "unbanned". Bans now apply
  regardless, and a full ban list (32) says so.
- The dashboard's client table no longer reorders itself while you use it (it was
  sorted by activity and redrawn every few seconds, so a Ban click could land on the
  wrong device). Clients are listed by IP.
- Wi-Fi setup could save a secured network without its password: the board then
  couldn't join, fell back to setup mode and stopped answering DNS. Setup is now two
  steps: tap a network, then a page with its name filled in asks for the password
  (required for secured networks, 8 to 63 characters), and the board checks it before
  saving. If a saved network doesn't join, the setup page says which one failed.

## [0.2.1] - 2026-10-18

Two fixes found testing v0.2.0 on hardware. Update from the dashboard (it offers the
update when it opens); settings are kept.

### Fixed

- Wi-Fi setup page: a hidden network typed under _Other network_ could be saved as the
  first listed network, which was preselected. Nothing is preselected now, and typing a
  name selects _Other network_.
- Dashboard chart: on a short time span the x-axis could show the same time twice. Ticks
  now fall on round times (every 5 s, 1 min, 5 min, ...).

### Changed

- The Wi-Fi setup page's scan buffers are allocated only in setup mode, giving back
  about 2 KB of RAM in normal operation.

## [0.2.0] - 2026-10-18

A redesigned dashboard with live charts, a friendlier Wi-Fi setup page and a new web
installer. Update from the dashboard (_Device → Check for updates_ on older versions);
settings are kept. From this version the dashboard checks for updates by itself.

### Changed

- Redesigned dashboard: a block-rate headline, stat tiles with trend lines, a live
  queries-per-minute chart (allowed vs blocked, with hover details), a breakdown of how
  queries were answered, upstream health with latency trends, per-client bars and a
  client filter, removable rule chips, health meters, a section menu and light/dark
  themes (follows the system, or pick one). The charts use what the page has seen since
  it opened; nothing new runs on the board.
- The dashboard checks for firmware updates when it opens and shows a banner when one
  is available (no more _Check for updates_ click).
- Wi-Fi setup page: tap a network from a list with signal strength and lock icons
  (duplicates and hidden networks removed, strongest first), _Other network_ for hidden
  ones, show-password toggle, clearer saved and error pages; works without JavaScript.
- Web installer: new layout with numbered steps, troubleshooting, the current version
  and a browser-support message; the GitHub Pages site gets a 404 page.

## [0.1.5] - 2026-10-18

Faster recovery after an internet outage, and a daily blocklist. Update from the
dashboard (_Device → Check for updates_); settings are kept.

### Fixed

- After an internet outage (e.g. ISP maintenance) lookups could keep failing for up to
  5 minutes once the connection was back, because every provider had backed off. When
  every upstream fails at once the board now retries every 10 s, recovers within
  seconds, and resets the other upstreams to "unknown" instead of leaving a stale
  "down" on the dashboard (plain DNS too, once encrypted DNS is back).

### Changed

- The default blocklist is now rebuilt daily (was weekly). If nothing changed, the
  file isn't re-uploaded, so boards skip the download.
- The default time zone is now `UTC0` (was a fixed regional zone), so the daily
  update runs at 02:00 UTC until you set yours under _Settings → Time zone_ (POSIX TZ
  string; the field shows examples). Boards that already saved settings keep their
  zone.
- README rewritten: highlights, a comparison with Pi-hole and the C3 original, a
  contents list and a flow diagram.

## [0.1.4] - 2026-10-17

The dashboard now reports the result of an update. You see it on updates made
_from_ v0.1.4 onward: updating a v0.1.3 board still ends at "installed, rebooting..."
(reload the page after a few seconds).

### Fixed

- After _Download & flash_ the dashboard stayed on "installed, rebooting...". It now waits
  for the device to come back and shows the version it runs (or that the update rolled
  back, or to reload the page if the device takes longer than 3 minutes).

## [0.1.3] - 2026-10-17

Update from the dashboard (_Device → Check for updates_) on v0.1.2. From this release
on, the update check knows when a future release can't be installed over the air.

### Added

- The dashboard update check refuses releases it can't install safely: a release that
  needs a USB flash from the running version (`minUpdateFrom` in `update.json`, set from
  `installer/min-update-from`), or an `update.json` format it doesn't know (`schema`).
  It shows why, with a link to the release notes. Boards can still skip versions.

## [0.1.2] - 2026-10-17

From this release on, the dashboard can update the board itself (_Device → Check for
updates_). Boards on v0.1.1 or older don't have the button: update them once from the
dashboard with `firmware-esp32s3-v0.1.2.bin` (v0.1.1) or over USB (v0.1.0).

### Added

- Dashboard _Device → Check for updates_: compares the running version with the latest
  release and, with **Download & flash**, downloads the firmware into the browser from
  GitHub Pages and installs it through the normal upload (same password, health check
  and rollback). Releases now also publish `firmware-esp32s3.bin` and `update.json` to
  Pages. The dashboard's Content-Security-Policy allows fetches to that site only.
  Build-time `UPDATE_BASE_URL` points forks at their own Pages site.

## [0.1.1] - 2026-10-15

Bug fixes from testing v0.1.0 on the board (dashboard updates, rollback, upstream
failover with a blackholed or impersonated server, plain-DNS fallback on and off).

**Upgrading from v0.1.0:** v0.1.0 can't install updates from its dashboard (first fix
below), so flash this release once over USB:

- from source with PlatformIO (`pio run -e esp32s3 -t upload`): settings, Wi-Fi and
  the dashboard password are kept;
- or with the [web installer](https://denzilrdz.github.io/esp32-s3-adblock/): its
  image covers the settings area, so you set up Wi-Fi and the dashboard password again
  (the downloaded blocklist is kept).

From v0.1.1 on, updates from the dashboard work and keep everything.

### Fixed

- Firmware updates from the dashboard crashed the board mid-upload (task watchdog in
  the web task) and never installed; the old firmware kept running. Uploads of
  firmware and blocklists now keep the watchdog fed. Verified on hardware, including
  the automatic rollback of an unhealthy update.
- Boot no longer logs dozens of `task_wdt: esp_task_wdt_reset: task not found` errors
  (ESP-IDF 5 reports watchdog feeds from tasks that aren't subscribed).
- When the primary upstream stopped answering (blocked port or dead address), the
  board restarted every ~18 s (task watchdog) and DNS stopped working. It now marks
  that upstream down and keeps answering through the next one.
- Failover from an unreachable upstream is fast: the TCP connect stage is capped at
  1 s, and an upstream is no longer marked down for a query that reached it too late
  to answer (this had taken the healthy Quad9 down too, for ~30 s of SERVFAIL).
- Settings pasted with spaces around them (e.g. a custom DoT IP) are accepted.
- A failed DNS-over-HTTPS connection no longer triggers a burst of reconnect attempts
  (one per queued query); queued queries move to the next upstream.
- After a restart, the dashboard showed the last successful blocklist update as failed
  (its OK flag wasn't saved with the result).

## [0.1.0] - 2026-10-15

First release of the ESP32-S3 fork of
[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock).
Tested on an ESP32-S3-DevKitC-1 (WROOM-1-N16R8): Wi-Fi setup, DNS-over-TLS, the
blocklist download and blocking, the response cache, DNS over TCP and the dashboard
password setup.

### Added

- Built on Arduino-ESP32 3.3.12 / ESP-IDF 5.5.5 (mbedTLS 3.6) through the pioarduino
  PlatformIO platform, pinned to release 55.03.312-1 (ESP-IDF 4.4, used upstream, no
  longer gets security fixes).
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
- Daily blocklist update at 02:00 local time with ETag, streaming validation, atomic swap
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
- Blocklist downloads verify HTTPS certificates and refuse redirects to plain HTTP,
  and follow GitHub's long (~900-character) release-asset redirect.

### Security

- GitHub Actions hardening: workflows audited with zizmor (auditor persona) and
  actionlint in CI and pre-commit; checkout credentials not persisted; per-job
  least-privilege permissions; job timeouts; no template expansion in scripts;
  release builds never use caches; Sigstore build-provenance attestations for
  release binaries; Dependabot cooldown; CODEOWNERS for CI and security-relevant
  paths.

### Removed

- ESP32-C3 and classic ESP32 support (this fork is ESP32-S3 only: PSRAM and 16 MB
  flash are required), upstream's 40-bit blocklist format, the Japanese README,
  the C3 web-installer binaries and the C3 SuperMini enclosure.

[Unreleased]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.2.7...HEAD
[0.2.7]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/denzilrdz/esp32-s3-adblock/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/denzilrdz/esp32-s3-adblock/releases/tag/v0.1.0
