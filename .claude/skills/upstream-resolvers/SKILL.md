---
name: upstream-resolvers
description: How encrypted upstream DNS works and how to change it. Use when touching DoT/DoH/plain-UDP transports, the fallback chain, the upstream health state machine, the response cache, TLS settings/certificate verification, or when adding a new upstream DNS provider.
---

# Upstream resolvers, fallback chain, cache

Design: [ARCHITECTURE.md §7](../../../docs/ARCHITECTURE.md).

## Code

| Piece | File |
|---|---|
| Transport interface (strategy) | `lib/core/upstream/transport.h` |
| DoT framing, DoH HTTP/1.1 codec (Content-Length only, no chunked) | `lib/core/upstream/framing.{h,cpp}` |
| Health state machine | `lib/core/upstream/health.{h,cpp}` |
| Forwarder: chain, in-flight table, hedging, deadlines | `lib/core/upstream/forwarder.{h,cpp}` |
| Response cache | `lib/core/cache/response_cache.{h,cpp}` |
| Provider table + chain order from settings | `lib/core/config/config.cpp` (`buildChain`) |
| ESP32 transports (DoT, DoH, UDP) | `src/platform/transports.{h,cpp}` on `src/platform/tls_stream.{h,cpp}` |
| Task (`dns_up`) and cache wiring | `src/tasks/dns_service.{h,cpp}` |
| Tests | `test/test_upstream`, `test/test_cache`, `test/test_config` |

## Defaults

Built by `config::buildChain()` from the settings (primary = Cloudflare, secondary =
Quad9 by default):

| Order | Transport | IP:port | Verify name |
|---|---|---|---|
| 1–2 | DoT (primary) | 1.1.1.1:853, 1.0.0.1:853 | `cloudflare-dns.com` |
| 3–4 | DoT (secondary) | 9.9.9.9:853, 149.112.112.112:853 | `dns.quad9.net` |
| 5–6 | DoH (POST, HTTP/1.1), if `up_doh` | 1.1.1.1:443, 1.0.0.1:443 | `cloudflare-dns.com` |
| 7–8 | plain UDP, if `up_plain` | 1.1.1.1:53, 9.9.9.9:53 | — |

Changing upstream settings on the dashboard restarts the device (transports are
created at boot in `startDnsService()`).

## Platform facts (Arduino 3.3.12 / IDF 5.5 / mbedTLS 3.6, verified in the SDK headers)

- **TLS:** `platform::TlsStream` drives mbedTLS directly on an lwIP socket:
  `mbedtls_ssl_set_hostname(<verify name>)` while connecting to the IP literal
  (we verify the name, never the IP), CA bundle via `esp_crt_bundle_attach` from
  `<esp_crt_bundle.h>`, `mbedtls_ssl_conf_min_tls_version(TLS1_2)`, hardware RNG.
  TLS 1.3 is off in the prebuilt libs, so resumption uses TLS 1.2 tickets.
- **Session resumption:** `esp_tls` has no client-session API in this SDK, which is
  why `TlsStream` exists; it keeps the ticket with `mbedtls_ssl_get_session` /
  `mbedtls_ssl_set_session`.
- **Memory:** mbedTLS buffers are internal RAM only, about 45 KB per session. At
  most 2 sessions (one DNS + one transient for failover or the blocklist download).
- **Certificate dates aren't checked** (`MBEDTLS_HAVE_TIME_DATE` off), so DoT
  works before NTP sync.
- **Idle close:** Cloudflare and Quad9 close idle DoT connections after about 10 s.
  Reconnect lazily with resumption; don't send keep-warm queries.
- **Quad9 DoH needs HTTP/2** (HTTP/1.1 gets 505), so it's not usable here.

## Health state machine

`Unknown → Up ⇄ Degraded → Down → Probing → Up/Down` (a failed connect is just a failure).
- 3 consecutive failures → Down.
- Probe backoff: 1 s, 2 s, 4 s … max 300 s, ±20 % jitter.
- The forwarder uses the first encrypted upstream that is not Down (or Down with its
  backoff elapsed: that query is the probe).
- Plain UDP is chosen only when every encrypted upstream is Down. A query whose
  encrypted upstreams merely failed gets SERVFAIL, never a plain-text retry.
- Tests: `test/test_upstream/`, using `FakeTransport` + `FakeClock`. Assert every
  transition.

## Timing

- Total deadline 2.5 s per query.
- Hedge to the next healthy upstream after 1.2 s.
- SERVFAIL at the deadline.
- Blocking budget: one `submit()`/`poll()` call starts a connect only if it fits in
  `maxBlockingMs` (4 s); `dns_up` feeds the watchdog after **each** call (a queue of
  them crash-looped the board with a dead primary).
- Connect: TCP stage capped at 1 s in `TlsStream`, TLS handshake gets the rest of the
  3 s. A full handshake measured ~1.5 s on the S3: don't lower the total below ~2.5 s.
- Blame at the deadline only if the upstream had `hedgeAfterMs` since the send; a
  failed transport reroutes every query assigned to it (incl. queued DoH ones).
- Test failover on hardware: Primary = custom with IP `192.0.2.1` (never answers),
  Secondary = quad9; certificate check: custom IP `1.1.1.1` with a wrong TLS name.
- At most `kMaxRepliesPerPoll` (64) replies are read per transport per `poll()`, so
  a flood of forged UDP replies can't monopolise the upstream task.
- In-flight table: 32 slots. Each upstream query gets a fresh random ID; a reply
  must match ID **and** question.

## Plain fallback

Used only when every encrypted upstream is Down. Log once per transition at WARN:
`upstream: ALL encrypted upstreams down — using PLAIN DNS (visible to ISP)`. The
dashboard shows a red banner. Clear AD on these answers. Strict mode
(`allow_plain_fallback=false`) → SERVFAIL instead.

## Cache

- Key: lowercase wire qname + qtype + qclass + DO bit.
- Store with OPT stripped. Rewrite TTLs to `ttl - age` on serve.
- Negative TTL = min(SOA TTL, SOA MINIMUM), ≤ 3 h, or 30 s if there's no SOA.
- Never cache SERVFAIL/REFUSED/TC.
- Fixed pool and slab arena in PSRAM: **no malloc after boot**.
- Flush on upstream config change.

## Adding a provider

1. Confirm it supports DoT on 853 (or DoH over **HTTP/1.1** with POST
   `application/dns-message`). Test from the Mac:
   ```bash
   kdig -d @<ip> +tls-ca +tls-hostname=<name> example.com     # brew install knot
   curl -sv --http1.1 -H 'content-type: application/dns-message' \
     --data-binary @q.bin https://<ip>/dns-query -o /dev/null   # must be 200
   ```
2. Check its certificate chains to a root in the IDF bundle (`openssl s_client
   -connect <ip>:853 -servername <name> -showcerts`).
3. Users can already use any DoT provider via the **custom** upstream setting
   (IP, second IP, TLS name, optional DoH). To make it a built-in choice: add a
   `Provider` value + `ProviderInfo` in `lib/core/config/config.{h,cpp}`
   (`providerName`, `parseProvider`, `info`), and an `<option>` in the dashboard
   settings form (`src/web/page.h`).
4. Native tests in `test/test_config`: chain order and names for the new provider.
5. Document it in the README configuration table.
