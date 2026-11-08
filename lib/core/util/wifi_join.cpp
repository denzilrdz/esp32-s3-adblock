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
