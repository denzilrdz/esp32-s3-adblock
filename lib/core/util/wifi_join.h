#pragma once
// Wi-Fi join at boot: whether a failed join retries or opens the setup portal.
//
// A network the board has joined before (with the saved credentials) is retried every
// few seconds for as long as it takes: after a power cut the board usually boots
// before the router does. Only a repeated password rejection opens the portal (the
// router's password changed). Credentials that never worked (a new network, a typo)
// open the portal after the first failed attempt, as before.

#include <cstdint>

namespace util {

enum class JoinFailure : uint8_t {
  kNotFound,  // network not on the air (router off or booting, out of range)
  kPassword,  // the access point rejected the password
  kOther,     // anything else, including a timeout without a reason
};

// Maps an ESP-IDF wifi_err_reason_t (station disconnect reason) to a failure kind.
JoinFailure classifyDisconnect(uint16_t reason);

enum class JoinAction : uint8_t { kRetry, kSetupPortal };

class JoinRetryPolicy {
 public:
  // Consecutive password rejections before a known network gives up.
  static constexpr int kMaxPasswordFailures = 3;

  explicit JoinRetryPolicy(bool joinedBefore) : joinedBefore_(joinedBefore) {}

  // Called after each failed attempt.
  JoinAction onFailure(JoinFailure failure);

 private:
  bool joinedBefore_;
  int passwordFailures_ = 0;
};

}  // namespace util
