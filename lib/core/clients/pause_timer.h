#pragma once
// The dashboard's "pause blocking": for a number of seconds, or until resumed. Works on
// 64-bit monotonic milliseconds, so it has no millis() wraparound (49.7 days). Kept in
// RAM on purpose: a restart turns blocking back on.

#include <cstdint>

namespace clients {

class PauseTimer {
 public:
  // seconds == 0: paused until resume().
  void pause(uint64_t nowMs, uint32_t seconds) {
    paused_ = true;
    resumeAtMs_ = seconds ? nowMs + static_cast<uint64_t>(seconds) * 1000 : 0;
  }
  void resume() {
    paused_ = false;
    resumeAtMs_ = 0;
  }
  // Also ends a timed pause that is due.
  bool blockingOn(uint64_t nowMs) {
    if (paused_ && resumeAtMs_ && nowMs >= resumeAtMs_) resume();
    return !paused_;
  }
  // 0 when blocking is on or paused until resumed.
  uint32_t resumeInSeconds(uint64_t nowMs) const {
    if (!paused_ || !resumeAtMs_ || nowMs >= resumeAtMs_) return 0;
    return static_cast<uint32_t>((resumeAtMs_ - nowMs) / 1000);
  }

 private:
  bool paused_ = false;
  uint64_t resumeAtMs_ = 0;
};

}  // namespace clients
