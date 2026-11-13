#pragma once
// Decides what to do with a valid client query before cache/upstream. Implemented by
// the application (blocklist, banned clients, pause); see src/main.cpp.

#include <cstdint>

#include "dns/message.h"
#include "dns/rewrite_reply.h"

namespace dns {

enum class PolicyAction {
  kForward,  // cache / upstream
  kBlock,    // sinkhole (EDE 15 "Blocked")
  kBan,      // client is banned: sinkhole everything (EDE 17 "Filtered")
  kRewrite,  // a DNS rewrite applies: answer from the RewriteAnswer (rewrite_reply.h)
};

class IQueryPolicy {
 public:
  virtual ~IQueryPolicy() = default;
  // Called from the DNS task for every valid query: must be fast and never block
  // for long (no network, no flash writes). `clientIpv4` is in network byte order.
  // `rewrite` is filled when the result is kRewrite.
  virtual PolicyAction decide(const Query& q, uint32_t clientIpv4, RewriteAnswer& rewrite) = 0;
};

// What the policy order below needs from the application (bans, rewrites, pause,
// lists). Implemented by app::AppPolicy; every call must be fast and non-blocking.
class IPolicySources {
 public:
  virtual ~IPolicySources() = default;
  virtual bool banned(uint32_t clientIpv4) = 0;  // also notes the client as seen
  virtual bool rewrite(const Query& q, RewriteAnswer& out) = 0;
  virtual bool blockingOn() = 0;            // false while blocking is paused
  virtual bool listed(const Query& q) = 0;  // custom allow > custom block > main list
  virtual void record(uint32_t clientIpv4, bool blocked) = 0;
};

// The policy order (ARCHITECTURE.md §5.6/§5.7), security-relevant and so tested here:
//  1. the device's own lookups (127.0.0.0/8) skip everything;
//  2. a banned client gets kBan, whatever else applies;
//  3. DNS rewrites, also while blocking is paused, and before the lists;
//  4. the blocking pause;
//  5. the lists.
// `clientIpv4` is in network byte order.
inline PolicyAction decidePolicy(IPolicySources& src, const Query& q, uint32_t clientIpv4,
                                 RewriteAnswer& rewrite) {
  const uint8_t* ip = reinterpret_cast<const uint8_t*>(&clientIpv4);
  if (ip[0] == 127) return PolicyAction::kForward;
  if (src.banned(clientIpv4)) return PolicyAction::kBan;
  if (src.rewrite(q, rewrite)) {
    src.record(clientIpv4, false);
    return PolicyAction::kRewrite;
  }
  const bool blocked = src.blockingOn() && src.listed(q);
  src.record(clientIpv4, blocked);
  return blocked ? PolicyAction::kBlock : PolicyAction::kForward;
}

}  // namespace dns
