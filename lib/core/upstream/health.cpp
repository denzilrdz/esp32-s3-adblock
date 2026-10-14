#include "upstream/health.h"

namespace upstream {

const char* healthStateName(HealthState s) {
  switch (s) {
    case HealthState::kUnknown: return "unknown";
    case HealthState::kUp: return "up";
    case HealthState::kDegraded: return "degraded";
    case HealthState::kDown: return "down";
    case HealthState::kProbing: return "probing";
  }
  return "?";
}

void UpstreamHealth::onSuccess(uint32_t latencyMs) {
  state_ = HealthState::kUp;
  failures_ = 0;
  backoffMs_ = 0;
  nextProbeMs_ = 0;
  stats_.ok++;
  stats_.lastLatencyMs = latencyMs;
}

void UpstreamHealth::onFailure(uint64_t nowMs, uint32_t random) {
  stats_.failed++;
  failures_++;
  const bool wasDown = state_ == HealthState::kProbing || state_ == HealthState::kDown;
  if (!wasDown && failures_ < cfg_.failuresToDown) {
    state_ = HealthState::kDegraded;
    return;
  }
  if (wasDown && backoffMs_ > 0) {
    backoffMs_ = backoffMs_ >= cfg_.maxBackoffMs / 2 ? cfg_.maxBackoffMs : backoffMs_ * 2;
  } else {
    backoffMs_ = cfg_.baseBackoffMs;
  }
  // Spread probes by +/- jitterPercent so several devices don't retry in lockstep.
  const uint32_t jitter = backoffMs_ / 100 * cfg_.jitterPercent;
  const uint32_t delay = backoffMs_ - jitter + (jitter ? random % (2 * jitter + 1) : 0);
  state_ = HealthState::kDown;
  nextProbeMs_ = nowMs + delay;
}

}  // namespace upstream
