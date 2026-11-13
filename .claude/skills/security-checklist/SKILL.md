---
name: security-checklist
description: Security checklist for this firmware. Use before committing changes to the web dashboard/API, captive portal, OTA (firmware or blocklist), config/secrets handling, TLS/upstream code, or any parser of network input (DNS, HTTP, blocklist files).
---

# Security review checklist

Threat model and controls: [ARCHITECTURE.md §9](../../../docs/ARCHITECTURE.md). The
device sits in the path of every DNS query on the LAN: treat every byte from the
network as hostile.

## 1. Network input (DNS, HTTP bodies, blocklist files, upstream replies)

- [ ] Every read is bounds-checked against the received length; no `strcpy`, no
      unchecked `memcpy`, no `sprintf` (use `snprintf` and check the result).
- [ ] Lengths from the wire (RDLENGTH, label length, Content-Length, header count)
      are validated before use, and integer overflow is considered (`uint16` + 12).
- [ ] Name decompression has a loop/hop limit and never points forward past `len`.
- [ ] Upstream replies are accepted only if ID **and** question match an in-flight
      entry.
- [ ] Downloaded blocklists pass the full validation in the `blocklist` skill
      **before** they replace anything.
- [ ] Native tests cover malformed and truncated input for any parser you touched.

## 2. Web dashboard / API

- [ ] Every state-changing route is **POST** and starts with
      `guard(Access::kAuth)` in `src/web/dashboard.cpp` (Host check, POST,
      `X-Requested-With: adblock`, Origin/Referer, session cookie or Basic Auth vs the PBKDF2 hash,
      per-client lockout, setup-code gate). Uploads use `check()` at
      `UPLOAD_FILE_START`, **and** their "done" handler starts with
      `uploadDoneAllowed()` (a request without a file part never runs the upload
      callback, so a flag from an earlier upload must not authorize it).
- [ ] Routes are registered with `route()` (`BoundedRoute`: 413 for bodies over 8 KB
      or a negative Content-Length, before the library buffers them), never
      `server.on()` / `onNotFound()`.
- [ ] Anything that checks a password (login, password change, future re-auth)
      goes through `verifyPassword()`: lockout + 1 s delay. Never call
      `PasswordStore::verify()`/`change()` on user input without it.
- [ ] Data GET routes call `guard(Access::kRead)` (login + Host check); only the
      page shell and 404 use `guard(Access::kPublic)`. Never send
      `WWW-Authenticate` (it pops up the browser's login box over the page's own).
- [ ] The page's CSP (`pageCsp()` in `dashboard.cpp`) keeps `connect-src` to
      `'self'` plus the update origin only; a new external fetch needs its origin
      added there deliberately, never `*`.
- [ ] All values rendered into HTML are escaped (`htmlEscape`); JSON strings are
      escaped (`jsonEscape`); no `innerHTML` with server data in `page.h`, use
      `textContent`. `tools/test_web_pages.py` checks the pages (skill `web-ui`).
- [ ] Inputs are validated (domain syntax, IPs, numeric ranges), with the **same**
      function on every path that sets the value (dashboard and settings import:
      e.g. `config::validBlocklistUrl()`), including length limits of the storage it
      ends up in.
- [ ] Failed-login backoff still applies (per client + fixed 1 s delay); no endpoint
      leaks passwords, the password hash, the setup code, `OTA_PASS` or Wi-Fi
      credentials. The setup code is only ever printed to the serial console.
- [ ] Responses to unauthenticated users reveal nothing beyond the static page
      shell (no stats, config, clients or version).

## 3. OTA

- [ ] Auth is checked at `UPLOAD_FILE_START`, every later chunk is ignored if it
      failed, and the done handler re-checks its own request.
- [ ] Rollback decisions (`diag::otaVerdict()`) never depend on something an
      unauthenticated LAN host can block (e.g. the single web task): that would
      let anyone force a downgrade. Only missing Wi-Fi/DNS rolls back.
- [ ] Firmware images are not signed yet (ARCHITECTURE.md §15 W11): anything that
      widens who can upload (new route, new auth path) needs that weighed.
- [ ] With a signing key configured, the image hash is verified **before**
      `Update.end(true)`; on failure, `Update.abort()`.
- [ ] The rollback health check still gates `esp_ota_mark_app_valid_cancel_rollback()`.
- [ ] ArduinoOTA stays disabled unless `OTA_PASS` is a real 10+ char password.

## 4. TLS / upstream

- [ ] No `setInsecure()`, no `skip_common_name`, and no `MBEDTLS_SSL_VERIFY_NONE`
      anywhere.
- [ ] A CA in the news (compromised or distrusted root)? The firmware's bundle is
      ESP-IDF's, fixed at framework release: add the root's exact common name to
      `util::kDistrustedRoots` (`lib/core/util/ca_bundle.h`), check it is in the
      bundle (`strings firmware.bin | grep '<name>'`), and expect `[tls] CA bundle:
    N roots, M distrusted removed` at boot. Remove the entry once the framework
      bundle drops the root. Dependabot alerts on `certifi` only cover the dev tools.
- [ ] Certificate dates: the prebuilt mbedTLS doesn't check them;
      `TlsStream::peerDatesValid()` does once the clock is synced. A new TLS client
      path (not `esp_http_client`) must do the same.
- [ ] The verify hostname is set for every IP-literal connection.
- [ ] The plain-DNS fallback is logged and visible on the dashboard; AD is cleared
      on it.

## 5. Secrets

- [ ] `git diff --cached --name-only | grep -E 'secrets\.h$'` prints nothing.
- [ ] No real passwords, tokens, keys or Wi-Fi names in code, tests, docs or
      commit messages.
- [ ] New secret settings: compile-time default in `secrets.example.h`
      (placeholder), runtime value in NVS, never logged.

## 6. Resource exhaustion

- [ ] Fixed limits on queues, connections (TCP/53 ≤ 2, HTTP), cache, custom rules
      and client table; when full, degrade (SERVFAIL / 503 / replace the stalest
      entry) rather than allocate or stop working until a reboot.
- [ ] No unbounded `String` concatenation driven by client input.
- [ ] Every loop a client can keep alive has a **total** deadline, not only a
      per-call timeout (`sendAllWithDeadline`), and fits the 5 s watchdog.
- [ ] Shared pools give each client a share when they run short (`InFlightLimiter`:
      enforced only near exhaustion, so a lone busy client isn't refused on an idle
      board); a router relaying DNS for the LAN is one client, so shares are
      fractions, not small numbers.
- [ ] Health / circuit-breaker logic counts one failure per event, not per query
      stuck on it (`blameSilence()`): a burst must not take a provider down, least
      of all the encrypted ones (plain fallback leaks every name).
- [ ] Listen backlogs and transient sockets fit the 16-socket budget
      (ARCHITECTURE.md §11).

## 7. Lessons from past findings (check these patterns explicitly)

- **Bounded work:** loops over network input (replies per poll, frames per read)
  have a hard cap; blocking connects fit a time budget under the 5 s watchdog.
- **Per-client fairness:** one client (e.g. TCP pipelining, reconnect loops) must
  not drain shared pools; count resources until they are actually released.
- **Timeouts can't be skipped:** idle/partial-frame deadlines apply even while work
  is in flight.
- **Lock-free code:** store-then-load handshakes between threads need seq_cst
  atomics, not acquire/release.
- **Fail closed after partial steps:** if a step released a resource (e.g.
  `prepareSwap()`), every later failure path must restore it.
- **Lockouts:** never add a global lockout any client can trigger (DoS on the
  owner); throttle with fixed per-failure cost instead.
- **Defaults:** public placeholder passwords must never authenticate.
- **Transport security:** HTTPS only, including every redirect hop; no runtime
  scripts from CDNs on pages that flash firmware (vendor + pin by hash).
- **Untracked files:** never overwrite `src/secrets.h` (or other gitignored user files)
  without looking at it first.
- **Locks on the hot path** (audit 2026-11): file I/O or a log line under a mutex
  the DNS tasks take stalled every query. Copy under the lock, act outside it.
- **Third-party data is input too:** the daily blocklist build drops entries that
  would block the update site, DNS or NTP (`PROTECTED` in `build_blocklist.py`) and
  refuses size jumps; cache entries never mix checking-disabled answers with
  validated ones.
- **Early randomness:** before Wi-Fi, `esp_random()` is pseudo-random; secrets made
  then use `bootloader_random_enable()`.

## 8. CI / GitHub Actions changes

- [ ] `.venv/bin/zizmor --persona=auditor .github/` and `.venv/bin/actionlint` are
      clean (also run by pre-commit and CI).
- [ ] New actions are pinned to a full commit SHA from the action's own repo, with a
      `# vX.Y.Z` comment (Dependabot updates both, after a 7-day cooldown).
- [ ] Job `permissions` are minimal and commented; workflow default is `{}`.
- [ ] No `pull_request_target`/`workflow_run` triggers; no untrusted `${{ }}` in `run:`.
- [ ] A deploy job `needs:` every job whose failure should stop it (Pages after the
      release exists); attestation checks pin `--signer-workflow` and `--source-ref`.
- [ ] Known gap: the toolchain (pioarduino platform and packages) is fetched by URL
      without a hash check; a change there deserves a manual SHA-256 check.

## Quick scans

```bash
git grep -nE 'setInsecure|strcpy|sprintf\(|VERIFY_NONE|skip_common_name'
git grep -nE 'innerHTML *=' src/web  # must print nothing
git grep -nE '\bs\.on\(|onNotFound\(' src/web/dashboard.cpp  # must print nothing (BoundedRoute)
tools/lint.sh
```

Report findings with file:line and a concrete failure scenario. Fix or explicitly
accept each one before committing.
