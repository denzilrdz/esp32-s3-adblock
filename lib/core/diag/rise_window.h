#pragma once
// How much a since-boot counter rose over the last few minutes (queries_dropped in
// GET /api/health). The maintenance task calls sample() about once a minute; rise()
// compares the current total with the oldest sample still inside the window.
//
// Counters are RAM totals that start at 0 on every boot, so the window starts with a
// (boot, 0) sample: a burst in the first minutes counts, and nothing carries over from
// before a restart. Not thread-safe: one owner (the maintenance task).

#include <cstddef>
#include <cstdint>

namespace diag {

class RiseWindow {
 public:
  static constexpr size_t kSlots = 16;  // > window / sample interval (10 min / 1 min)

  explicit RiseWindow(uint32_t windowMs) : windowMs_(windowMs) { push(0, 0); }

  void sample(uint32_t nowMs, uint32_t total) { push(nowMs, total); }

  // total minus the oldest sample taken within the last windowMs (the newest sample if
  // every one is older). A counter that went backwards (can't, but) rises by 0.
  uint32_t rise(uint32_t nowMs, uint32_t total) const {
    uint32_t base = 0;
    bool found = false;
    uint32_t newestAge = UINT32_MAX;
    uint32_t newestValue = 0;
    for (size_t k = 0; k < count_; k++) {
      const Sample& s = samples_[(head_ + kSlots - count_ + k) % kSlots];  // oldest first
      const uint32_t age = nowMs - s.atMs;
      if (!found && age <= windowMs_) {
        base = s.value;
        found = true;
      }
      if (age < newestAge) {
        newestAge = age;
        newestValue = s.value;
      }
    }
    if (!found) base = newestValue;
    return total > base ? total - base : 0;
  }

 private:
  struct Sample {
    uint32_t atMs = 0;
    uint32_t value = 0;
  };
  void push(uint32_t atMs, uint32_t value) {
    samples_[head_] = {atMs, value};
    head_ = (head_ + 1) % kSlots;
    if (count_ < kSlots) count_++;
  }

  uint32_t windowMs_;
  Sample samples_[kSlots];
  size_t head_ = 0;
  size_t count_ = 0;
};

}  // namespace diag
