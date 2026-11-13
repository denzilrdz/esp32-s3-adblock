#pragma once
// When a freshly updated firmware image (still "pending verify") is kept or rolled
// back (ARCHITECTURE.md §9). The bootloader only rolls back on the next reset, so both
// a running image that never gets healthy and one stuck before loop() runs (e.g. a
// Wi-Fi regression in setup(): known networks are retried forever) must reset it.

#include <cstdint>

namespace diag {

enum class OtaVerdict : uint8_t { kWait, kMarkValid, kRollback };

struct OtaHealthInput {
  uint32_t uptimeMs = 0;
  bool wifi = false;        // connected with an address
  bool dnsRunning = false;  // the DNS service started
  bool webAnswers = false;  // the dashboard answered a local request (routes, auth, page)
};

constexpr uint32_t kOtaHealthyAfterMs = 60000;    // healthy for this long: keep it
constexpr uint32_t kOtaGiveUpMs = 5 * 60000;      // still not healthy: roll back
constexpr uint32_t kOtaBootGuardMs = 10 * 60000;  // setup() never finished: roll back

// Upstream reachability is deliberately not required: an ISP outage must not roll
// back good firmware.
inline OtaVerdict otaVerdict(const OtaHealthInput& in) {
  if (in.wifi && in.dnsRunning && in.webAnswers && in.uptimeMs > kOtaHealthyAfterMs)
    return OtaVerdict::kMarkValid;
  if (in.uptimeMs > kOtaGiveUpMs) return OtaVerdict::kRollback;
  return OtaVerdict::kWait;
}

}  // namespace diag
