#pragma once
// Scripted randomness: returns queued values first, then a simple deterministic sequence.

#include <deque>

#include "hal/random.h"

class FakeRandom final : public hal::IRandom {
 public:
  uint32_t next32() override {
    if (!queued_.empty()) {
      uint32_t v = queued_.front();
      queued_.pop_front();
      return v;
    }
    state_ = state_ * 1664525u + 1013904223u;
    return state_;
  }

  void push(uint32_t v) { queued_.push_back(v); }

 private:
  std::deque<uint32_t> queued_;
  uint32_t state_ = 12345;
};
