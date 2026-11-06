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

}  // namespace dns
