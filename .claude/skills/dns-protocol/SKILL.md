---
name: dns-protocol
description: Rules and checklist for DNS packet handling. Use before changing anything in lib/core/dns/ or the policy/reply code — query validation, EDNS0/OPT, truncation and TCP, blocked A/AAAA/HTTPS replies, local answers, Extended DNS Errors — or when debugging a malformed-reply report.
---

# DNS protocol rules

Code: `lib/core/dns/message.{h,cpp}`, `lib/core/dns/name.{h,cpp}`,
`lib/core/blocklist/policy.{h,cpp}`. Design: [ARCHITECTURE.md §5](../../../docs/ARCHITECTURE.md).

## Incoming query validation (in order)

| Condition | Action |
|---|---|
| len < 12, or QR = 1 | drop silently |
| OPCODE ≠ 0 | NOTIMP |
| QDCOUNT ≠ 1 | FORMERR |
| bad name (label > 63, name > 255, compression in question, overruns packet) | FORMERR |
| QCLASS ≠ IN | REFUSED |
| > 1 OPT, or malformed OPT | FORMERR |
| OPT version > 0 | BADVERS (extended RCODE 16) |
| QTYPE = ANY (255) | NOTIMP |
| source IP not private/link-local/loopback | drop (not an open resolver) |

## Replies we synthesize

- **Blocked A** → `0.0.0.0`; **blocked AAAA** → `::`, TTL = `blocked_ttl` (10 s).
- **Blocked HTTPS/SVCB/other types** → NOERROR, empty answer (NODATA), plus a
  synthetic SOA in the authority section with TTL and MINIMUM = `blocked_ttl`.
- **Never NXDOMAIN for blocked names.** RFC 8020 lets resolvers prune the whole
  subtree.
- Flags: QR = 1, RA = 1, AA = 0, AD = 0; copy ID, RD, CD; echo the question exactly.
- If the query had OPT: add OPT (UDP size 1232, DO echoed) + EDE option 15 with
  info-code 15 "Blocked" (17 "Filtered" for a banned client).
- **Local:** `localhost`/`*.localhost` → 127.0.0.1 / ::1; RFC 6303 private reverse
  zones → NXDOMAIN; `use-application-dns.net` → NXDOMAIN; iCloud Private Relay
  canaries → NXDOMAIN only if enabled.
- **Upstream timeout / all upstreams down** → SERVFAIL (never silence).

## Forwarded answers

- Strip the upstream OPT; rebuild our own for the client (EDNS is hop-by-hop).
- AD: pass through only if the upstream channel was authenticated (DoT/DoH) **and**
  the client set AD or DO. Clear it on plain-UDP fallback.
- Restore the client's ID; preserve the RD from the query.

## Size limits and TCP

- UDP limit = the client's OPT size clamped to [512, 1232], or 512 without OPT.
- Too big → header + question + OPT, TC = 1, ANCOUNT = NSCOUNT = 0 (and ARCOUNT = 1
  if OPT). Client retries over TCP/53.
- TCP/53: 2-byte big-endian length prefix, ≤ 4 connections, 10 s idle timeout.

## Checklist for changing DNS code

1. Every read is bounds-checked against the packet length. No pointer arithmetic
   past `len`.
2. No allocation, `String` or logging above DEBUG on the hot path.
3. Add native tests in `test/test_dns/` for the happy path **and**:
   - truncated header, truncated question, label overrun;
   - compression loop / pointer in question;
   - QDCOUNT = 0 and 2;
   - OPT with bad length;
   - an oversized answer that triggers TC.
4. Check `ID`, flags, all four counts and the OPT in assertions, not just the
   answer RDATA.
5. Verify on hardware with `dig`:
   ```bash
   dig @<ip> doubleclick.net A        # 0.0.0.0, status NOERROR
   dig @<ip> doubleclick.net AAAA     # ::
   dig @<ip> doubleclick.net HTTPS    # NOERROR, ANSWER 0, AUTHORITY 1 (SOA), EDE 15
   dig @<ip> example.com +dnssec      # flags include ad
   dig @<ip> txt-big.example +bufsize=512   # tc set, then +tcp works
   ```
6. Run the `security-checklist` skill: this code handles untrusted network input.

## RFCs

1035 (core), 2181 §9 (TC), 2308 (negative caching), 6303 (local zones),
6840 §5.7–5.8 (AD), 6891 (EDNS0), 7766 (TCP), 7830/8467 (padding), 8020 (NXDOMAIN
cut), 8482 (ANY), 8914 (EDE), 9460 (SVCB/HTTPS).
