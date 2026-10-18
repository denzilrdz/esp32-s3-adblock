#pragma once
// Per-client statistics, bans and the global blocking pause. Read from the DNS tasks
// (through AppPolicy) and changed from the web task, so every method locks briefly.

#include <Arduino.h>

#include <cstdint>
#include <vector>

#include "clients/ban_list.h"
#include "clients/pause_timer.h"
#include "platform/rtos.h"

namespace app {

struct ClientInfo {
  uint32_t ip = 0;  // network byte order
  uint8_t mac[6] = {0};
  uint32_t blocked = 0;
  uint32_t allowed = 0;
  uint32_t lastSeenMs = 0;
  bool banned = false;
};

class ClientTable {
 public:
  static constexpr int kMaxClients = 96;
  static constexpr int kMaxBans = clients::BanList::kMax;

  enum class BanResult { kBanned, kUnbanned, kListFull };

  void loadBans();  // from /banned.txt

  // DNS path ------------------------------------------------------------------
  // Returns true if the client is banned (creating its entry on first sight).
  bool checkBanned(uint32_t ip);
  void record(uint32_t ip, bool blocked);
  bool blockingOn();

  // Web / maintenance -------------------------------------------------------------
  BanResult toggleBan(uint32_t ip);
  void pause(uint32_t seconds);  // 0 = until resumed
  void resume();
  uint32_t resumeInSeconds();
  void tick();                // auto-resume a timed pause
  void resolvePendingMacs();  // ARP lookups inside the lwIP thread
  std::vector<ClientInfo> snapshot();
  uint32_t totalBlocked();
  uint32_t totalAllowed();

 private:
  struct Entry {
    ClientInfo info;
    bool macPending = false;
    uint8_t macTries = 0;
  };
  Entry* find(uint32_t ip, bool create);  // caller holds mutex_
  void saveBans();                        // caller holds mutex_

  platform::Mutex mutex_;
  Entry entries_[kMaxClients];
  int count_ = 0;
  clients::BanList bans_;  // the only source of truth for bans (persisted)
  clients::PauseTimer pause_;
  uint32_t totalBlocked_ = 0;
  uint32_t totalAllowed_ = 0;
};

}  // namespace app
