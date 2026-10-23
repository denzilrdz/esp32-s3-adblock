#include "diag/liveness.h"

namespace diag {

int LivenessMonitor::add(const char* name, uint32_t limitMs, bool armed) {
  const int id = count_.load();
  if (id >= kMaxActivities) return -1;
  Activity& a = activities_[id];
  a.name = name;
  a.limitMs = limitMs;
  a.lastBeat.store(now());
  a.armed.store(armed);
  count_.store(id + 1);  // published last: other tasks only see complete entries
  return id;
}

void LivenessMonitor::beat(int id) {
  if (valid(id)) activities_[id].lastBeat.store(now());
}

void LivenessMonitor::arm(int id) {
  if (!valid(id)) return;
  activities_[id].lastBeat.store(now());  // before armed: check() never sees a stale beat
  activities_[id].armed.store(true);
}

void LivenessMonitor::disarm(int id) {
  if (valid(id)) activities_[id].armed.store(false);
}

const char* LivenessMonitor::check() {
  const uint32_t t = now();
  lastCheck_.store(t ? t : 1);  // 0 means "never ran"
  const int n = count_.load();
  for (int i = 0; i < n; i++) {
    const Activity& a = activities_[i];
    if (!a.armed.load()) continue;
    if (t - a.lastBeat.load() > a.limitMs) return a.name;
  }
  return nullptr;
}

bool LivenessMonitor::checkerStalled(uint32_t limitMs) const {
  const uint32_t last = lastCheck_.load();
  return last != 0 && now() - last > limitMs;
}

}  // namespace diag
