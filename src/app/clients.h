#pragma once
// Per-client statistics, bans and the global blocking pause. Read from the DNS tasks
// (through AppPolicy) and changed from the web task, so every method locks briefly.
// mutex_ is on the DNS hot path: never hold it across file I/O or logging. The ban
// file has its own lock (fileMutex_, always taken before mutex_).

#include <Arduino.h>

#include <cstdint>
#include <vector>

#include "clients/ban_list.h"
#include "clients/client_directory.h"
#include "clients/pause_timer.h"
#include "platform/rtos.h"

namespace app {

using ClientInfo = clients::ClientInfo;

class ClientTable {
 public:
  static constexpr int kMaxClients = clients::ClientDirectory::kMax;
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
  clients::BanList bans();                         // copy (settings export)
  void replaceBans(const clients::BanList& list);  // settings import
  void pause(uint32_t seconds);                    // 0 = until resumed
  void resume();
  uint32_t resumeInSeconds();
  void tick();                // auto-resume a timed pause
  void resolvePendingMacs();  // ARP lookups inside the lwIP thread
  std::vector<ClientInfo> snapshot();
  uint32_t totalBlocked();
  uint32_t totalAllowed();

 private:
  clients::ClientEntry& obtain(uint32_t ip);  // caller holds mutex_
  // Writes the current ban list to flash. Caller holds fileMutex_, not mutex_.
  void saveBans();

  platform::Mutex fileMutex_;
  platform::Mutex mutex_;
  clients::ClientDirectory dir_;
  clients::BanList bans_;  // the only source of truth for bans (persisted)
  clients::PauseTimer pause_;
  uint32_t totalBlocked_ = 0;
  uint32_t totalAllowed_ = 0;
};

}  // namespace app
