#include "util/civil_time.h"

namespace util {

namespace {

// Howard Hinnant's days_from_civil / civil_from_days (public domain algorithms).
int64_t daysFromCivil(int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

void civilFromDays(int64_t z, int& y, int& m, int& d) {
  z += 719468;
  const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(z - era * 146097);
  const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const int64_t yy = static_cast<int64_t>(yoe) + era * 400;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const unsigned mp = (5 * doy + 2) / 153;
  d = static_cast<int>(doy - (153 * mp + 2) / 5 + 1);
  m = static_cast<int>(mp < 10 ? mp + 3 : mp - 9);
  y = static_cast<int>(yy + (m <= 2));
}

}  // namespace

CivilTime civilFromUnix(int64_t unixSeconds, int32_t utcOffsetSeconds) {
  const int64_t local = unixSeconds + utcOffsetSeconds;
  int64_t days = local / 86400;
  int64_t secs = local % 86400;
  if (secs < 0) {
    secs += 86400;
    days -= 1;
  }
  CivilTime t;
  civilFromDays(days, t.year, t.month, t.day);
  t.hour = static_cast<int>(secs / 3600);
  t.minute = static_cast<int>((secs % 3600) / 60);
  t.second = static_cast<int>(secs % 60);
  return t;
}

int64_t unixFromCivil(const CivilTime& local, int32_t utcOffsetSeconds) {
  const int64_t days =
      daysFromCivil(local.year, static_cast<unsigned>(local.month), static_cast<unsigned>(local.day));
  return days * 86400 + local.hour * 3600 + local.minute * 60 + local.second - utcOffsetSeconds;
}

}  // namespace util
