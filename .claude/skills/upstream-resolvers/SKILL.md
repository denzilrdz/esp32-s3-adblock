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
| ESP32 transports | `src/platform/dot_transport.cpp`, `doh_transport.cpp`, `udp_transport.cpp` |
| Task | `src/tasks/upstream_task.cpp` |

## Defaults

| Order | Transport | IP:port | Verify name |
|---|---|---|---|
| 1 | DoT | 1.1.1.1:853, alt 1.0.0.1 | `cloudflare-dns.com` |
| 2 | DoT | 9.9.9.9:853, alt 149.112.112.112 | `dns.quad9.net` |
| 3 | DoH (POST, HTTP/1.1) | 1.1.1.1:443, alt 1.0.0.1 | `cloudflare-dns.com` |
| 4 | plain UDP (if `allow_plain_fallback`) | 9.9.9.9:53, 1.1.1.1:53 | — |

## Platform facts (Arduino 2.0.17 / IDF 4.4, verified)

- **TLS API:** use `esp_tls` with `cfg.common_name = "<verify name>"` and
  `cfg.crt_bundle_attach = esp_crt_bundle_attach`. Connect to the IP literal.
  mbedTLS 2.28 doesn't match IP SANs, so the verify name is mandatory.
- **Session resumption:** `esp_tls_get_client_session` is **not** in the prebuilt
  lib. Use `mbedtls_ssl_get_session` / `mbedtls_ssl_set_session` on the context.
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
  `maxBlockingMs` (4 s), so unreachable upstreams can't trip the 5 s watchdog.
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
   kdig -d @<ip> +tls-ca +tls-hostname=<name> example.com     # knot-dnsutils
   curl -sv --http1.1 -H 'content-type: application/dns-message' \
     --data-binary @q.bin https://<ip>/dns-query -o /dev/null   # must be 200
   ```
2. Check its certificate chains to a root in the IDF bundle (`openssl s_client
   -connect <ip>:853 -servername <name> -showcerts`).
3. Add an entry to the provider table in `lib/core/config/config.cpp` (IP(s), port,
   transport, verify name), not in the transports.
4. Add a native test: chain ordering, plus config validation of the new entry.
5. Document it in the README's upstream table.
