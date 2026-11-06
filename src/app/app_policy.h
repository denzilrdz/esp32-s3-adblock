#pragma once
// The DNS policy: banned clients, then DNS rewrites (they also apply while blocking is
// paused and beat the allow/block lists), then the blocking pause and the blocklist
// matcher (custom allow > custom block > main list, parent domains). The device's own
// lookups skip all of it. Called from the DNS tasks for every valid query, so it only
// takes short locks.

#include <lwip/sockets.h>

#include "app/blocklist_manager.h"
#include "app/clients.h"
#include "app/rewrites.h"
#include "dns/query_policy.h"

namespace app {

class AppPolicy final : public dns::IQueryPolicy {
 public:
  AppPolicy(ClientTable& clients, BlocklistManager& blocklist, RewriteManager& rewrites)
      : clients_(clients), blocklist_(blocklist), rewrites_(rewrites) {}

  dns::PolicyAction decide(const dns::Query& q, uint32_t clientIpv4, dns::RewriteAnswer& rewrite) override {
    if ((ntohl(clientIpv4) >> 24) == 127) return dns::PolicyAction::kForward;  // the device's own lookups
    if (clients_.checkBanned(clientIpv4)) return dns::PolicyAction::kBan;
    if (rewrites_.resolve(q, rewrite)) {
      clients_.record(clientIpv4, false);
      return dns::PolicyAction::kRewrite;
    }
    const bool blocked = clients_.blockingOn() &&
                         blocklist_.matcher().match(q.qname, q.qnameLen) == blocklist::MatchResult::kBlocked;
    clients_.record(clientIpv4, blocked);
    return blocked ? dns::PolicyAction::kBlock : dns::PolicyAction::kForward;
  }

 private:
  ClientTable& clients_;
  BlocklistManager& blocklist_;
  RewriteManager& rewrites_;
};

}  // namespace app
