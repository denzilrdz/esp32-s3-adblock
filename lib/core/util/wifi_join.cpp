#include "util/wifi_join.h"

namespace util {

JoinAction JoinRetryPolicy::onFailure() {
  if (!joinedBefore_) return JoinAction::kSetupPortal;
  if (failures_ < 30) failures_++;  // capped: the delay saturates long before this
  uint32_t d = kFirstDelayMs;
  for (int i = 1; i < failures_ && d < kMaxDelayMs; i++) d *= 2;
  delayMs_ = d < kMaxDelayMs ? d : kMaxDelayMs;
  return JoinAction::kRetry;
}

}  // namespace util

namespace util {

WifiStep WifiSupervisor::tick(bool connected, uint32_t nowMs) {
  WifiStep st;
  if (connected) {
    if (down_) {
      st.cameBack = true;
      st.downMs = nowMs - downSince_;
      st.attempt = attempts_;
    }
    down_ = false;
    return st;
  }
  if (!down_) {
    down_ = true;
    downSince_ = nowMs;
    delay_ = kFirstRetryMs;
    nextAt_ = nowMs + delay_;
    attempts_ = 0;
    st.wentDown = true;
    return st;
  }
  st.downMs = nowMs - downSince_;
  if (st.downMs >= kRebootAfterMs) {
    st.action = WifiAction::kReboot;
  } else if (static_cast<int32_t>(nowMs - nextAt_) >= 0) {
    st.action = WifiAction::kReconnect;
    st.attempt = ++attempts_;
    delay_ = delay_ * 2 < kMaxRetryMs ? delay_ * 2 : kMaxRetryMs;
    nextAt_ = nowMs + delay_;
  }
  return st;
}

}  // namespace util
