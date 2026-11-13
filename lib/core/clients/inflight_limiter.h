#pragma once
// Caps how many forwarded (cache-miss) queries one client may have waiting for an
// upstream answer at once. The pending pool is shared by the whole LAN: without a cap,
// one chatty or compromised device asking for random names during an upstream slowdown
// filled all of it and every other client got SERVFAIL (audit 2026-11).
//
// A router that relays DNS for the LAN (docs/ROUTER_SETUP.md, option B) appears as one
// client, so the cap is a share of the pool (half by default), not a small number.
//
// Not thread-safe: used only by dns_io (UDP); TCP has its own per-connection limits.

#include <cstddef>
#include <cstdint>

namespace clients {

class InFlightLimiter {
 public:
  static constexpr size_t kMaxTracked = 64;  // >= the pending pool: every holder fits

  explicit InFlightLimiter(uint16_t perClient = 16) : perClient_(perClient ? perClient : 1) {}

  // Takes one slot for `ip` (any byte order, used only as a key). False if it already
  // holds perClient slots (or, defensively, if the table is full).
  bool tryAcquire(uint32_t ip) {
    Entry* free = nullptr;
    for (Entry& e : entries_) {
      if (e.count && e.ip == ip) {
        if (e.count >= perClient_) return false;
        e.count++;
        return true;
      }
      if (!e.count && !free) free = &e;
    }
    if (!free) return false;
    free->ip = ip;
    free->count = 1;
    return true;
  }

  // Gives back a slot taken by tryAcquire(ip). Unknown ips are ignored.
  void release(uint32_t ip) {
    for (Entry& e : entries_)
      if (e.count && e.ip == ip) {
        e.count--;
        return;
      }
  }

  uint16_t heldBy(uint32_t ip) const {
    for (const Entry& e : entries_)
      if (e.count && e.ip == ip) return e.count;
    return 0;
  }
  uint16_t perClient() const { return perClient_; }

 private:
  struct Entry {
    uint32_t ip = 0;
    uint16_t count = 0;
  };
  uint16_t perClient_;
  Entry entries_[kMaxTracked];
};

}  // namespace clients
