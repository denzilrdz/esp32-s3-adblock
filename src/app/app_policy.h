#pragma once
// The DNS policy (order in dns::decidePolicy, tested natively): banned clients, then
// DNS rewrites (they also apply while blocking is paused and beat the allow/block
// lists), then the blocking pause and the blocklist matcher (custom allow > custom
// block > main list, parent domains). The device's own lookups skip all of it. Called
// from the DNS tasks for every valid query, so it only takes short locks.

#include "app/blocklist_manager.h"
#include "app/clients.h"
#include "app/rewrites.h"
#include "dns/query_policy.h"

namespace app {

class AppPolicy final : public dns::IQueryPolicy, private dns::IPolicySources {
 public:
  AppPolicy(ClientTable& clients, BlocklistManager& blocklist, RewriteManager& rewrites)
      : clients_(clients), blocklist_(blocklist), rewrites_(rewrites) {}

  dns::PolicyAction decide(const dns::Query& q, uint32_t clientIpv4, dns::RewriteAnswer& rewrite) override {
    return dns::decidePolicy(*this, q, clientIpv4, rewrite);
  }

 private:
  bool banned(uint32_t ip) override { return clients_.checkBanned(ip); }
  bool rewrite(const dns::Query& q, dns::RewriteAnswer& out) override { return rewrites_.resolve(q, out); }
  bool blockingOn() override { return clients_.blockingOn(); }
  bool listed(const dns::Query& q) override {
    return blocklist_.matcher().match(q.qname, q.qnameLen) == blocklist::MatchResult::kBlocked;
  }
  void record(uint32_t ip, bool blocked) override { clients_.record(ip, blocked); }

  ClientTable& clients_;
  BlocklistManager& blocklist_;
  RewriteManager& rewrites_;
};

}  // namespace app
