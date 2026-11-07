#include "sched/reboot_schedule.h"

#include <cstring>
#include <initializer_list>

namespace sched {

const char* rebootModeName(RebootMode m) {
  switch (m) {
    case RebootMode::kDaily: return "daily";
    case RebootMode::kWeekly: return "weekly";
    case RebootMode::kOff: break;
  }
  return "off";
}

bool parseRebootMode(const char* s, RebootMode& out) {
  if (!s) return false;
  for (RebootMode m : {RebootMode::kOff, RebootMode::kDaily, RebootMode::kWeekly})
    if (!strcmp(s, rebootModeName(m))) return out = m, true;
  return false;
}

RebootScheduler::RebootScheduler(const hal::IClock& clock, hal::IKeyValueStore& kv, int minYear)
    : clock_(clock), kv_(kv), minYear_(minYear) {
  uint32_t v = 0;
  if (kv_.getU32(kLastKey, v)) last_ = v;
}

bool RebootScheduler::clockValid() const {
  return clock_.wallClockSynced() && clock_.localTime().year >= minYear_;
}

bool RebootScheduler::dayMatches(const util::CivilTime& date) const {
  switch (plan_.mode) {
    case RebootMode::kDaily: return true;
    case RebootMode::kWeekly: return util::weekday(date) == plan_.weekday;
    case RebootMode::kOff: break;
  }
  return false;
}

bool RebootScheduler::due() {
  dueDate_ = 0;
  if (plan_.mode == RebootMode::kOff || !clockValid()) return false;
  const util::CivilTime now = clock_.localTime();
  const uint32_t nowMin = static_cast<uint32_t>(now.hour * 60 + now.minute);
  const uint32_t target = plan_.hour * 60u + plan_.minute;
  const uint64_t upMin = clock_.monotonicMs() / 60000;
  // Today's slot, or yesterday's when its window runs past midnight (23:30 + 60 min).
  for (int back = 0; back <= 1; back++) {
    const util::CivilTime day = back ? util::addDays(now, -1) : now;
    const uint32_t since = nowMin + (back ? 1440u : 0u);  // minutes since that day's midnight
    if (since < target || since >= target + kWindowMinutes || !dayMatches(day)) continue;
    if (day.dateKey() == last_) return false;                        // already done
    if (upMin < (since - target) + kFreshBootMinutes) return false;  // started just now
    dueDate_ = day.dateKey();
    return true;
  }
  return false;
}

void RebootScheduler::markRebooting() {
  if (!dueDate_) return;
  last_ = dueDate_;
  kv_.setU32(kLastKey, last_);
}

bool RebootScheduler::next(util::CivilTime& out) const {
  if (plan_.mode == RebootMode::kOff || !clockValid()) return false;
  const util::CivilTime now = clock_.localTime();
  const uint32_t nowMin = static_cast<uint32_t>(now.hour * 60 + now.minute);
  const uint32_t target = plan_.hour * 60u + plan_.minute;
  for (int i = 0; i <= 7; i++) {
    util::CivilTime d = util::addDays(now, i);
    if (!dayMatches(d) || d.dateKey() == last_ || (i == 0 && nowMin >= target)) continue;
    d.hour = plan_.hour;
    d.minute = plan_.minute;
    d.second = 0;
    out = d;
    return true;
  }
  return false;  // unreachable for daily/weekly
}

}  // namespace sched
