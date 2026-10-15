# Security policy

This device sits in the path of every DNS query on your network and accepts firmware
and blocklist updates, so security reports are very welcome.

## Supported versions

Only the latest release (and `main`) receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

- Email **denzil.rdz@gmail.com** with the subject `esp32-s3-adblock security`, or
- use GitHub's private reporting: _Security → Report a vulnerability_ on this repository.

Include the affected version or commit, the board, steps to
reproduce, and the impact you expect. You'll get an acknowledgement within 7 days; a
fix or a plan should follow within 30 days for confirmed issues. Credit is given in
the release notes unless you prefer otherwise.

## Scope and known limits

In scope: the firmware (DNS parsing, upstream DoT/DoH handling, blocklist download and
validation, dashboard/REST API, OTA), the blocklist builder and the CI workflows.

Known, documented limits (see [docs/ARCHITECTURE.md §9](docs/ARCHITECTURE.md)):

- The dashboard is plain HTTP with Basic Auth: anyone who can sniff your LAN can read
  the credentials. It is a LAN trust-boundary control, not encryption.
- The Wi-Fi setup access point is open during provisioning.
- Read-only status (`/api/stats`) is visible to everyone on the LAN.
- Blocklists are integrity-checked (CRC) and fetched over verified HTTPS only; they are
  not signed.
- Firmware images are not signed. OTA updates need the dashboard password (or
  `OTA_PASS`), and release files come with SHA-256 checksums and build-provenance
  attestations, but the device itself does not verify a signature.
- TLS certificates (upstream DNS, blocklist download) are checked against the CA bundle
  and the server name, but not their validity dates: the prebuilt mbedTLS is built
  without `MBEDTLS_HAVE_TIME_DATE`. An expired or not-yet-valid certificate from a
  trusted CA would be accepted.
- The firmware is built with the community pioarduino PlatformIO platform
  (Arduino-ESP32 3.3.12 / ESP-IDF 5.5.5), pinned to one release. Security fixes in
  ESP-IDF reach the device only when that pin is bumped.

Signed firmware and certificate date checks are planned
([docs/ARCHITECTURE.md §15](docs/ARCHITECTURE.md#15-platform-notes-and-roadmap)).
