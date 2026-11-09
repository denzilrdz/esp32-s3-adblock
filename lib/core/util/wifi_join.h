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

namespace util {

// While the board is running: Arduino's auto-reconnect gives up for good on some
// disconnect reasons (e.g. 202 AUTH_FAIL, 210-212 security mismatch), which a mesh router
// can report while it reboots, leaving the board offline until the 10-minute reboot.
// This drives our own reconnect attempts: the first 10 s after the drop, then 20 s later,
// then every 30 s, and asks for a reboot after 10 minutes down as a last resort.
enum class WifiAction : uint8_t { kNone, kReconnect, kReboot };

struct WifiStep {
  WifiAction action = WifiAction::kNone;
  bool wentDown = false;  // first tick without a connection
  bool cameBack = false;  // first tick connected again
  uint32_t downMs = 0;    // how long it has been (or was) down
  uint32_t attempt = 0;   // reconnect attempt number (with kReconnect)
};

class WifiSupervisor {
 public:
  static constexpr uint32_t kFirstRetryMs = 10000;
  static constexpr uint32_t kMaxRetryMs = 30000;
  static constexpr uint32_t kRebootAfterMs = 600000;

  // Called every couple of seconds with the current link state. Wrap-safe millis().
  WifiStep tick(bool connected, uint32_t nowMs);
  bool down() const { return down_; }

 private:
  bool down_ = false;
  uint32_t downSince_ = 0;
  uint32_t nextAt_ = 0;
  uint32_t delay_ = kFirstRetryMs;
  uint32_t attempts_ = 0;
};

}  // namespace util
