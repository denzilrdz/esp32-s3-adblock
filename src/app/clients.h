#pragma once
// Per-client statistics, bans and the global blocking pause. Read from the DNS tasks
// (through AppPolicy) and changed from the web task, so every method locks briefly.

#include <Arduino.h>

#include <cstdint>
#include <vector>

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
  static constexpr int kMaxBans = 32;

  void loadBans();  // from /banned.txt

  // DNS path ------------------------------------------------------------------
  // Returns true if the client is banned (creating its entry on first sight).
  bool checkBanned(uint32_t ip);
  void record(uint32_t ip, bool blocked);
  bool blockingOn();

  // Web / maintenance -------------------------------------------------------------
  bool toggleBan(uint32_t ip);
  void pause(uint32_t seconds);  // 0 = until resumed
  void resume();
  uint32_t resumeInSeconds();
  void tick();                   // auto-resume a timed pause
  void resolvePendingMacs();     // ARP lookups inside the lwIP thread
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
  bool isBanListed(uint32_t ip) const;
  void saveBans();

  platform::Mutex mutex_;
  Entry entries_[kMaxClients];
  int count_ = 0;
  uint32_t bans_[kMaxBans] = {0};
  int banCount_ = 0;
  bool blockingOn_ = true;
  uint32_t resumeAt_ = 0;  // millis(); 0 = paused indefinitely
  uint32_t totalBlocked_ = 0;
  uint32_t totalAllowed_ = 0;
};

}  // namespace app
