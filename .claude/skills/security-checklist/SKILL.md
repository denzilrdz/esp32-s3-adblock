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

- [ ] Every state-changing route is **POST** and calls `requireAuth()` (Basic Auth +
      `X-Requested-With` header + Origin/Referer host check).
- [ ] The `Host` header is checked (device IP or `*.local`): DNS-rebinding defence.
- [ ] All values rendered into HTML are escaped (`htmlEscape`); JSON strings are
      escaped (`jsonEscape`); no `innerHTML` with server data in `page.h`, use
      `textContent`.
- [ ] Inputs are validated (domain syntax, IPs, URL must be `https://`, numeric
      ranges).
- [ ] Failed-login backoff still applies; no endpoint leaks passwords, the password
      hash, `OTA_PASS` or Wi-Fi credentials.
- [ ] Responses to unauthenticated users don't reveal more than `/api/stats`
      already does.

## 3. OTA

- [ ] Auth is checked at `UPLOAD_FILE_START`, and every later chunk is ignored if
      it failed.
- [ ] With a signing key configured, the image hash is verified **before**
      `Update.end(true)`; on failure, `Update.abort()`.
- [ ] The rollback health check still gates `esp_ota_mark_app_valid_cancel_rollback()`.
- [ ] ArduinoOTA has a password set; it refuses to start with the placeholder
      password.

## 4. TLS / upstream

- [ ] No `setInsecure()`, no `skip_common_name`, and no `MBEDTLS_SSL_VERIFY_NONE`
      anywhere.
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

- [ ] Fixed limits on queues, connections (TCP/53 ≤ 4, HTTP), cache, custom rules
      and client table; when full, degrade (SERVFAIL / 503) rather than allocate.
- [ ] No unbounded `String` concatenation driven by client input.

## Quick scans

```bash
git grep -nE 'setInsecure|strcpy|sprintf\(|VERIFY_NONE|skip_common_name'
git grep -nE 'innerHTML' src/web
pio check -e native
```

Report findings with file:line and a concrete failure scenario. Fix or explicitly
accept each one before committing.
