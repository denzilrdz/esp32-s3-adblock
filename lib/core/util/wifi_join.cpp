#include "util/wifi_join.h"

namespace util {

JoinFailure classifyDisconnect(uint16_t reason) {
  // Values from ESP-IDF 5.5 esp_wifi_types_generic.h (wifi_err_reason_t).
  switch (reason) {
    case 201:  // WIFI_REASON_NO_AP_FOUND
    case 210:  // WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY
    case 211:  // WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD
    case 212:  // WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD
      return JoinFailure::kNotFound;
    case 15:   // WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT (WPA2 wrong password)
    case 202:  // WIFI_REASON_AUTH_FAIL (WPA3-SAE wrong password)
    case 204:  // WIFI_REASON_HANDSHAKE_TIMEOUT
      return JoinFailure::kPassword;
    default: return JoinFailure::kOther;
  }
}

JoinAction JoinRetryPolicy::onFailure(JoinFailure failure) {
  if (!joinedBefore_) return JoinAction::kSetupPortal;
  if (failure != JoinFailure::kPassword) {
    passwordFailures_ = 0;
    return JoinAction::kRetry;
  }
  return ++passwordFailures_ >= kMaxPasswordFailures ? JoinAction::kSetupPortal : JoinAction::kRetry;
}

}  // namespace util
