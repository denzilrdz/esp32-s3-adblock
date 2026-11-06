#pragma once
// Replies for DNS rewrites (dashboard "Rewrites", ARCHITECTURE.md §5.7): a name answered
// with a fixed IPv4/IPv6 address, or aliased to another name (CNAME), for a limited time.
//
//  - Address rewrites answer A/AAAA locally; a type without an address (AAAA when only
//    an IPv4 is set, HTTPS, MX, ...) gets NODATA, so the real answer can't bypass it.
//  - An alias answers with a CNAME chain (q.qname -> hop 1 -> ... -> hop n). If the
//    last hop has no rewrite of its own, its records come from upstream/cache and are
//    appended (names decompressed, TTLs capped); a CNAME query is answered with the
//    chain alone.
//  - Every TTL is capped at the rewrite's remaining lifetime (and kRewriteMaxTtl), so
//    clients let go of it soon after it is removed or expires. AD is never set.
//
// No allocation: everything works on caller buffers (DNS hot path).

#include <cstddef>
#include <cstdint>

#include "dns/message.h"

namespace dns {

constexpr size_t kMaxRewriteHops = 8;       // CNAMEs in one chain; more = SERVFAIL
constexpr size_t kRewriteChainBytes = 512;  // wire bytes for all hop names together
constexpr uint32_t kRewriteMaxTtl = 30;     // seconds; also never past the expiry

struct RewriteAnswer {
  enum class End : uint8_t {
    kAddress,  // answered locally (addresses below, possibly none for this type)
    kForward,  // resolve the last hop upstream
    kLoop,     // the chain loops or is too long: SERVFAIL
  };
  End end = End::kAddress;
  uint32_t ttl = kRewriteMaxTtl;
  uint8_t hops = 0;
  uint16_t nameOff[kMaxRewriteHops + 1] = {0};  // hop i = chain[nameOff[i] .. nameOff[i+1])
  uint8_t chain[kRewriteChainBytes] = {0};
  bool hasV4 = false;
  bool hasV6 = false;
  uint8_t v4[4] = {0};
  uint8_t v6[16] = {0};

  void clear();
  // Appends a hop (uncompressed wire name). False when the chain is full.
  bool addHop(const uint8_t* wire, size_t len);
  const uint8_t* hop(size_t i, size_t& len) const {
    len = static_cast<size_t>(nameOff[i + 1] - nameOff[i]);
    return chain + nameOff[i];
  }
  // The name whose records end the chain (q's own name when there are no hops).
  bool forwards() const { return end == End::kForward; }
};

// The query to send upstream / look up in the cache for a kForward rewrite: `q` with
// the last hop's name. False if `rw` has no hops or the name is not a valid query name.
bool rewriteTargetQuery(const Query& q, const RewriteAnswer& rw, Query& out);

// The complete client reply for a rewrite, like finalizeForClient(): client ID, RD/CD
// from the query, RA=1, AD=0, our own OPT if the client used EDNS, TC=1 if it doesn't
// fit `sizeLimit`. `target` is the upstream/cached answer (without OPT) to
// rewriteTargetQuery() for a kForward rewrite, or null to answer with the chain alone.
// Builds SERVFAIL for kLoop, a malformed target, a target rcode other than NOERROR /
// NXDOMAIN, or records that don't fit `cap`. Returns the length (0 only if `cap` can't
// hold even the error reply). `target` and `out` must not overlap.
size_t buildRewriteReply(const Query& q, const RewriteAnswer& rw, const uint8_t* target, size_t targetLen,
                         size_t sizeLimit, uint8_t* out, size_t cap);

}  // namespace dns
