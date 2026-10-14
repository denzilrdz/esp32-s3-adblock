#include "blocklist/matcher.h"

#include <algorithm>

namespace blocklist {

void DomainSet::add(const char* name, size_t len) {
  hashes_.push_back(hashDomain(name, len));
}

void DomainSet::finalize() {
  std::sort(hashes_.begin(), hashes_.end());
  hashes_.erase(std::unique(hashes_.begin(), hashes_.end()), hashes_.end());
}

bool DomainSet::contains(uint64_t hash48) const {
  return std::binary_search(hashes_.begin(), hashes_.end(), hash48);
}

void Matcher::setCustom(DomainSet block, DomainSet allow) {
  std::lock_guard<std::mutex> lock(customMutex_);
  customBlock_ = std::move(block);
  customAllow_ = std::move(allow);
}

MatchResult Matcher::match(const char* name, size_t len) const {
  if (len == 0) return MatchResult::kNone;
  {
    std::lock_guard<std::mutex> lock(customMutex_);
    if (customAllow_.size() &&
        forEachCandidate(name, len, [this](uint64_t h) { return customAllow_.contains(h); }))
      return MatchResult::kAllowed;
    if (customBlock_.size() &&
        forEachCandidate(name, len, [this](uint64_t h) { return customBlock_.contains(h); }))
      return MatchResult::kBlocked;
  }
  IndexHolder::ReadGuard g = index_.acquire();
  const IIndex* idx = g.get();
  if (idx && forEachCandidate(name, len, [idx](uint64_t h) { return idx->contains(h); }))
    return MatchResult::kBlocked;
  return MatchResult::kNone;
}

}  // namespace blocklist
