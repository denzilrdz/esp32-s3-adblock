#pragma once
// Pure calendar arithmetic (no libc time zones), so scheduling logic is testable and
// does not depend on the host's TZ settings.

#include <cstdint>

namespace util {

struct CivilTime {
  int year = 1970;
  int month = 1;   // 1..12
  int day = 1;     // 1..31
  int hour = 0;    // 0..23
  int minute = 0;  // 0..59
  int second = 0;  // 0..59

  // Compact sortable date key, e.g. 20261015.
  uint32_t dateKey() const { return static_cast<uint32_t>(year * 10000 + month * 100 + day); }
};

// Unix seconds + fixed UTC offset (seconds, e.g. +19800 for IST) -> local civil time.
CivilTime civilFromUnix(int64_t unixSeconds, int32_t utcOffsetSeconds);

// Inverse of civilFromUnix for a local civil time at a fixed UTC offset.
int64_t unixFromCivil(const CivilTime& local, int32_t utcOffsetSeconds);

}  // namespace util
