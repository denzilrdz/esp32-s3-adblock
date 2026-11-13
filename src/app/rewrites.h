#pragma once
// Temporary DNS rewrites on the device (ARCHITECTURE.md §5.7): the rules::RewriteTable
// in PSRAM behind a mutex, persisted to /rewrites.txt. resolve() runs in the DNS tasks
// (short lock, no allocation); add/remove/list in the web task; tick() in the
// maintenance task (restores saved rewrites once the clock is synced, saves changes
// made before that).

#include <Arduino.h>

#include <atomic>
#include <vector>

#include "dns/message.h"
#include "dns/rewrite_reply.h"
#include "hal/clock.h"
#include "hal/file_system.h"
#include "hal/logger.h"
#include "platform/rtos.h"
#include "rules/rewrites.h"

namespace app {

class RewriteManager {
 public:
  RewriteManager(hal::IFileSystem& fs, const hal::IClock& clock, hal::ILogger& log)
      : fs_(fs), clock_(clock), log_(log) {}

  bool begin();  // boot: allocate the table and load the file

  // DNS tasks. False if no rewrite applies to q.
  bool resolve(const dns::Query& q, dns::RewriteAnswer& out);

  // Web task.
  rules::RewriteStatus add(const String& domain, const String& target, uint32_t minutes);
  rules::RewriteStatus remove(const String& domain, const String& target);
  std::vector<rules::RewriteView> list();

  void tick();  // maintenance task, every few seconds

 private:
  // Writes the table if it changed since the last save. Serializes under mutex_ (short)
  // and writes the file outside it, so DNS lookups never wait for flash. False while
  // the clock is unknown (tick() retries) or on a write error (retried after a minute).
  bool save();

  hal::IFileSystem& fs_;
  const hal::IClock& clock_;
  hal::ILogger& log_;
  rules::RewriteTable* table_ = nullptr;  // PSRAM, lives for the whole uptime
  platform::Mutex mutex_;
  platform::Mutex fileMutex_;     // one save at a time (web and maintenance tasks)
  uint32_t changes_ = 0;          // bumped on every change (mutex_)
  uint32_t saved_ = 0;            // changes_ at the last successful save (mutex_)
  uint64_t retryAtMs_ = 0;        // after a failed write
  std::atomic<size_t> count_{0};  // lets resolve() skip the lock when there is nothing
};

}  // namespace app
