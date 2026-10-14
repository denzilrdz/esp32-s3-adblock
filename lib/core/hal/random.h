#pragma once

#include <cstdint>

namespace hal {

// Source of unpredictable numbers (esp_random() on the device). Used for DNS
// transaction IDs, so it must not be a plain PRNG seeded with a constant.
class IRandom {
 public:
  virtual ~IRandom() = default;
  virtual uint32_t next32() = 0;

  uint16_t next16() { return static_cast<uint16_t>(next32()); }

  // Uniform-enough value in [0, bound) for jitter; bound must be > 0.
  uint32_t uniform(uint32_t bound) { return next32() % bound; }
};

}  // namespace hal
