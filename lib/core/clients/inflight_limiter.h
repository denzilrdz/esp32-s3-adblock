#pragma once
// Shares the pending pool (forwarded, cache-miss queries waiting for an upstream) fairly
// when it runs short. Without a cap, one chatty or compromised device asking for random
// names during an upstream slowdown filled all of it and every other client got
// SERVFAIL (audit 2026-11). A hard cap was too strict (found on the board): a browser
// resolving 40 new names at once got SERVFAIL while nobody else was using DNS. So a
// client may go past its share while the pool has room, and is refused only when it
// holds its share and fewer than `reserve` slots are free: those stay for the others.
//
// A router that relays DNS for the LAN (docs/ROUTER_SETUP.md, option B) appears as one
// client, so the share is a fraction of the pool (half by default), not a small number.
//
// Not thread-safe: used only by dns_io (UDP); TCP has its own per-connection limits.

#include <cstddef>
#include <cstdint>

namespace clients {

class InFlightLimiter {
 public:
  static constexpr size_t kMaxTracked = 64;  // >= the pending pool: every holder fits

  explicit InFlightLimiter(uint16_t perClient = 16, uint16_t reserve = 8)
      : perClient_(perClient ? perClient : 1), reserve_(reserve) {}

  // Takes one slot for `ip` (any byte order, used only as a key). `poolFree` = slots
  // still free in the shared pool. False if `ip` already holds perClient slots and no more
  // than `reserve` are free (or, defensively, if the table is full).
  bool tryAcquire(uint32_t ip, size_t poolFree) {
    Entry* free = nullptr;
    for (Entry& e : entries_) {
      if (e.count && e.ip == ip) {
        if (e.count >= perClient_ && poolFree <= reserve_) return false;
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
  uint16_t reserve_;
  Entry entries_[kMaxTracked];
};

}  // namespace clients
