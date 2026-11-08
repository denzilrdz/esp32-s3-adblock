#pragma once
// Wi-Fi join at boot: whether a failed join retries or opens the setup portal.
//
// A network the board has joined before (with the saved credentials) is retried for as
// long as it takes, whatever the disconnect reason: after a power cut or a scheduled
// router reboot the board often starts first, and a mesh router can broadcast its name
// before it accepts clients, failing joins with handshake timeouts (reason 15/204) that
// look like a wrong password. Opening the portal there left the board cycling between
// the setup network and restarts. New Wi-Fi details for a known board: hold BOOT at
// power-on or use the dashboard's Forget Wi-Fi.
//
// Credentials that never worked (a new network, a typo) open the portal after the
// first failed attempt, as before.

#include <cstdint>

namespace util {

enum class JoinAction : uint8_t { kRetry, kSetupPortal };

class JoinRetryPolicy {
 public:
  static constexpr uint32_t kFirstDelayMs = 5000;
  static constexpr uint32_t kMaxDelayMs = 30000;

  explicit JoinRetryPolicy(bool joinedBefore) : joinedBefore_(joinedBefore) {}

  // Called after each failed attempt.
  JoinAction onFailure();

  // Pause before the next attempt: 5 s, doubling up to 30 s. Valid after onFailure().
  uint32_t retryDelayMs() const { return delayMs_; }

 private:
  bool joinedBefore_;
  int failures_ = 0;
  uint32_t delayMs_ = kFirstDelayMs;
};

}  // namespace util
