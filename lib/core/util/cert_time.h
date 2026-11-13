#pragma once
// Certificate validity dates against the synced wall clock.
//
// The prebuilt mbedTLS is built without MBEDTLS_HAVE_TIME_DATE, so it never checks a
// certificate's notBefore/notAfter: that lets DoT work before NTP has synced (the board
// has no RTC), but an expired (or revoked and leaked) upstream key stayed usable for a
// man-in-the-middle forever (audit 2026-11). platform::TlsStream checks the peer's
// chain with this after each handshake, once the clock is synced.

#include <cstdint>

#include "util/civil_time.h"

namespace util {

struct CertTime {
  int year = 0, mon = 0, day = 0, hour = 0, min = 0, sec = 0;  // UTC, as in the certificate
};

enum class CertValidity : uint8_t { kValid, kNotYetValid, kExpired };

// `slackSeconds` tolerates a clock that is a little off either way.
inline CertValidity certValidity(const CertTime& from, const CertTime& to, int64_t nowUnix,
                                 int64_t slackSeconds = 3600) {
  auto toUnix = [](const CertTime& t) {
    CivilTime c;
    c.year = t.year;
    c.month = t.mon;
    c.day = t.day;
    c.hour = t.hour;
    c.minute = t.min;
    c.second = t.sec;
    return unixFromCivil(c, 0);
  };
  if (nowUnix + slackSeconds < toUnix(from)) return CertValidity::kNotYetValid;
  if (nowUnix - slackSeconds > toUnix(to)) return CertValidity::kExpired;
  return CertValidity::kValid;
}

}  // namespace util
