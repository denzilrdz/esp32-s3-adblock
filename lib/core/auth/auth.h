#pragma once
// Dashboard authentication (ARCHITECTURE.md §9):
//  - PasswordStore: PBKDF2-HMAC-SHA256 hash + random salt in NVS; the compile-time
//    password from secrets.h is only a first-boot default. The public placeholder
//    password forces a change before anything else can be modified.
//  - LoginGuard: per-client lockout with exponential backoff after repeated failures.
//  - hostAllowed/originAllowed: reject requests through foreign hostnames (DNS
//    rebinding) and cross-site requests (CSRF).

#include <cstddef>
#include <cstdint>

#include "hal/clock.h"
#include "hal/kv_store.h"
#include "hal/random.h"
#include "util/sha256.h"

namespace auth {

constexpr const char* kPlaceholderPassword = "CHANGE_ME_WEB_PASSWORD";
constexpr uint32_t kIterations = 4096;
constexpr size_t kMinPasswordLength = 10;
constexpr size_t kMaxPasswordLength = 64;

class PasswordStore {
 public:
  static constexpr const char* kKey = "auth_pw";

  // `defaultUser`/`defaultPassword` come from secrets.h and must outlive the store.
  PasswordStore(hal::IKeyValueStore& kv, hal::IRandom& random, const char* defaultUser,
                const char* defaultPassword);

  const char* user() const { return user_; }
  // True while no password was set and the default is the public placeholder:
  // the dashboard then allows only setting a password.
  bool mustChange() const;
  bool hasStoredPassword() const { return stored_; }

  bool verify(const char* user, const char* password);
  // Returns false and a reason if the current password is wrong or the new one is
  // not acceptable.
  bool change(const char* current, const char* next, const char** why);

 private:
  void deriveKey(const char* password, const uint8_t* salt, uint8_t out[util::kSha256Size]) const;
  void cacheCredentials(const char* user, const char* password);
  bool cachedMatch(const char* user, const char* password) const;

  hal::IKeyValueStore& kv_;
  hal::IRandom& random_;
  const char* user_;
  const char* defaultPassword_;
  bool stored_ = false;
  uint8_t salt_[16] = {0};
  uint8_t hash_[util::kSha256Size] = {0};
  // SHA-256 of the last verified "user:password", so polling requests don't pay for
  // PBKDF2 every time. Cleared when the password changes.
  bool haveCache_ = false;
  uint8_t cache_[util::kSha256Size] = {0};
};

class LoginGuard {
 public:
  static constexpr int kFreeAttempts = 5;
  static constexpr uint32_t kBaseLockMs = 30000;
  static constexpr uint32_t kMaxLockMs = 300000;

  explicit LoginGuard(const hal::IClock& clock) : clock_(clock) {}

  bool allowed(uint32_t clientIp);
  void onFailure(uint32_t clientIp);
  void onSuccess(uint32_t clientIp);
  uint32_t retryAfterSeconds(uint32_t clientIp);

 private:
  struct Entry {
    uint32_t ip = 0;
    uint8_t failures = 0;
    uint32_t lockMs = 0;
    uint64_t lockedUntil = 0;
    uint64_t lastSeen = 0;
  };
  Entry* find(uint32_t ip, bool create);

  const hal::IClock& clock_;
  Entry entries_[16];
};

// `host` is the Host header (may carry ":port"). Allowed: the device IP, or
// "<hostname>" / "<hostname>.local" (case-insensitive).
bool hostAllowed(const char* host, const char* deviceIp, const char* hostname);

// For state-changing requests: if an Origin (or else Referer) header is present its
// host must pass hostAllowed(). Requests with neither (non-browser clients) pass;
// browsers always send Origin on cross-site POSTs.
bool originAllowed(const char* origin, const char* referer, const char* deviceIp, const char* hostname);

}  // namespace auth
