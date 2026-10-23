#pragma once
// Software watchdog for work the 5 s hardware task watchdog can't cover (ARCHITECTURE.md
// §4.3), so that a real hang still ends in a restart with its cause recorded:
//  - the web task: deliberately not on the hardware watchdog (Arduino's WebServer can
//    legitimately busy-wait for seconds on a slow client);
//  - the blocklist download: the hardware watchdog is paused around esp_http_client;
//  - the upstream task: its TLS I/O feeds the hardware watchdog per socket call, so an
//    endless loop of I/O would keep feeding it.
// Each activity beat()s while it makes progress; check() names one that has been silent
// past its limit. On the device check() runs from a periodic esp_timer, and the
// maintenance task (on the hardware watchdog) restarts the board if check() stops
// running, so the checker is watched too.
//
// Thread-safe without locks: beat/arm/disarm from any task, check from another. Times
// are 32-bit milliseconds compared by unsigned difference, so they survive the 49-day
// wrap (limits are minutes).

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "hal/clock.h"

namespace diag {

class LivenessMonitor {
 public:
  static constexpr int kMaxActivities = 6;

  explicit LivenessMonitor(const hal::IClock& clock) : clock_(clock) {}
  LivenessMonitor(const LivenessMonitor&) = delete;
  LivenessMonitor& operator=(const LivenessMonitor&) = delete;

  // Registers an activity at boot, before other tasks use the monitor. `name` must
  // outlive the monitor. Returns its id, or -1 when the table is full.
  int add(const char* name, uint32_t limitMs, bool armed);

  void beat(int id);    // the activity made progress
  void arm(int id);     // start watching (counts as a beat)
  void disarm(int id);  // stop watching, e.g. the download finished

  // The first armed activity silent for longer than its limit, or nullptr. Records the
  // time of the check for lastCheckMs().
  const char* check();
  // When check() last ran (32-bit ms), 0 before the first run.
  uint32_t lastCheckMs() const { return lastCheck_.load(); }
  // True if check() hasn't run for `limitMs` (the checker itself stopped).
  bool checkerStalled(uint32_t limitMs) const;

 private:
  struct Activity {
    const char* name = nullptr;
    uint32_t limitMs = 0;
    std::atomic<uint32_t> lastBeat{0};
    std::atomic<bool> armed{false};
  };

  uint32_t now() const { return static_cast<uint32_t>(clock_.monotonicMs()); }
  bool valid(int id) const { return id >= 0 && id < count_.load(); }

  const hal::IClock& clock_;
  Activity activities_[kMaxActivities];
  std::atomic<int> count_{0};
  std::atomic<uint32_t> lastCheck_{0};
};

}  // namespace diag
