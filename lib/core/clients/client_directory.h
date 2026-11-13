#pragma once
// The dashboard's per-client table: one entry per source IP seen by the DNS service,
// with counters and the MAC address once ARP finds it. Fixed size; when it is full,
// the client not seen for longest makes room. Before the 2026-11 audit entries were
// never freed: phones with private MAC addresses (new IP each time) or a host
// spoofing source addresses filled all 96 entries and every new device was invisible
// until a reboot.
//
// Not thread-safe: app::ClientTable wraps it in a mutex.

#include <cstdint>

namespace clients {

struct ClientInfo {
  uint32_t ip = 0;  // network byte order
  uint8_t mac[6] = {0};
  uint32_t blocked = 0;
  uint32_t allowed = 0;
  uint32_t lastSeenMs = 0;  // 32-bit milliseconds: compared by age, so wrap-safe
  bool banned = false;
};

struct ClientEntry {
  ClientInfo info;
  bool macPending = false;
  uint8_t macTries = 0;
};

class ClientDirectory {
 public:
  static constexpr int kMax = 96;

  ClientEntry* find(uint32_t ip) {
    for (int i = 0; i < count_; i++)
      if (entries_[i].info.ip == ip) return &entries_[i];
    return nullptr;
  }

  // Finds `ip`, or adds it (MAC lookup pending, seen now), replacing the client not
  // seen for longest when the table is full. `*created` tells the caller to fill in
  // anything it derives (e.g. the ban flag).
  ClientEntry& obtain(uint32_t ip, uint32_t nowMs, bool* created = nullptr) {
    if (ClientEntry* e = find(ip)) {
      if (created) *created = false;
      return *e;
    }
    int slot = count_;
    if (count_ < kMax) {
      count_++;
    } else {
      slot = 0;
      for (int i = 1; i < kMax; i++)
        if (nowMs - entries_[i].info.lastSeenMs > nowMs - entries_[slot].info.lastSeenMs) slot = i;
      evictions_++;
    }
    ClientEntry& e = entries_[slot];
    e = ClientEntry{};
    e.info.ip = ip;
    e.info.lastSeenMs = nowMs;
    e.macPending = true;
    if (created) *created = true;
    return e;
  }

  int count() const { return count_; }
  ClientEntry& at(int i) { return entries_[i]; }
  const ClientEntry& at(int i) const { return entries_[i]; }
  uint32_t evictions() const { return evictions_; }

 private:
  ClientEntry entries_[kMax];
  int count_ = 0;
  uint32_t evictions_ = 0;
};

}  // namespace clients
