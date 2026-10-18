#pragma once
// Per-upstream health state machine: a circuit breaker with exponential backoff.
//
//   Unknown --ok--> Up <--ok-- Degraded
//      |             |  --fail-->  |
//      +---fail----> Degraded --N fails--> Down --backoff elapsed--> Probing
//                                            ^                          |
//                                            +-------- fail ------------+  (backoff x2)
//   Probing --ok--> Up
//
// Connection setup (TCP/TLS) is the transport's concern; a failed connect is simply
// reported as a failure here.

#include <cstdint>

namespace upstream {

enum class HealthState : uint8_t { kUnknown, kUp, kDegraded, kDown, kProbing };

const char* healthStateName(HealthState s);

struct HealthConfig {
  uint32_t failuresToDown = 3;
  uint32_t baseBackoffMs = 1000;
  uint32_t maxBackoffMs = 300000;  // 5 min
  uint32_t jitterPercent = 20;
};

struct HealthStats {
  uint32_t ok = 0;
  uint32_t failed = 0;
  uint32_t lastLatencyMs = 0;
};

class UpstreamHealth {
 public:
  explicit UpstreamHealth(const HealthConfig& cfg = HealthConfig{}) : cfg_(cfg) {}

  HealthState state() const { return state_; }
  // Usable for a query now: anything but Down, or Down with its backoff elapsed.
  bool available(uint64_t nowMs) const { return state_ != HealthState::kDown || nowMs >= nextProbeMs_; }
  // Call when a Down upstream is picked after its backoff: the next result decides.
  void beginProbe() {
    if (state_ == HealthState::kDown) state_ = HealthState::kProbing;
  }

  void onSuccess(uint32_t latencyMs);
  // `random` supplies the jitter (any 32-bit value).
  void onFailure(uint64_t nowMs, uint32_t random);
  // Back to Unknown, keeping the stats: its recent failures weren't its own fault (e.g.
  // the local internet connection was down).
  void reset();
  // While Down/Probing: next probe no later than nowMs + maxMs, backoff at most maxMs.
  void capBackoff(uint64_t nowMs, uint32_t maxMs);

  uint32_t consecutiveFailures() const { return failures_; }
  uint32_t backoffMs() const { return backoffMs_; }
  uint64_t nextProbeMs() const { return nextProbeMs_; }
  const HealthStats& stats() const { return stats_; }

 private:
  HealthConfig cfg_;
  HealthState state_ = HealthState::kUnknown;
  uint32_t failures_ = 0;
  uint32_t backoffMs_ = 0;
  uint64_t nextProbeMs_ = 0;
  HealthStats stats_;
};

}  // namespace upstream
