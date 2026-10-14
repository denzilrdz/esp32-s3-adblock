#pragma once
// Time sources. Core logic never calls millis()/time() directly; it receives an IClock.

#include <cstdint>

#include "util/civil_time.h"

namespace hal {

class IClock {
 public:
  virtual ~IClock() = default;

  // Milliseconds since boot. Monotonic, never jumps; use for timeouts and backoff.
  virtual uint64_t monotonicMs() const = 0;

  // True once wall-clock time has been synchronised (NTP). Until then unixTime()
  // is meaningless and nothing time-of-day based may run.
  virtual bool wallClockSynced() const = 0;

  // Seconds since the Unix epoch (UTC). Only valid when wallClockSynced().
  virtual int64_t unixTime() const = 0;

  // Local civil time for the configured time zone. Only valid when wallClockSynced().
  virtual util::CivilTime localTime() const = 0;
};

}  // namespace hal
