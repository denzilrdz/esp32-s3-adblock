#pragma once
// Dashboard authentication (ARCHITECTURE.md §9):
//  - PasswordStore: PBKDF2-HMAC-SHA256 hash + random salt in NVS; the compile-time
//    password from secrets.h is only a first-boot default. A missing, weak or
//    placeholder default never authenticates: instead a random one-time setup code
//    (printed on the serial console, i.e. physical access) is required to set the
//    first password, so nobody else on the LAN can claim the device first.
//  - LoginGuard: per-client lockout with exponential backoff after repeated failures.
//    Deliberately no global lockout: that would let any LAN client lock the owner out.
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
  // True while no password was set and the default is missing/weak/placeholder:
  // the dashboard then allows only setting a password, using setupCode().
  bool mustChange() const;
  bool hasStoredPassword() const { return stored_; }
  // One-time code accepted as the "current password" while mustChange(). Changes on
  // every boot; empty when not needed. Print it to the serial console only.
  const char* setupCode() const { return setupCode_; }

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
  char setupCode_[16] = {0};
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
  // Returns the client's entry, or the shared overflow entry when every slot holds a
  // locked client (locked entries are never evicted, so a flood of new addresses can
  // neither flush an attacker's lock nor lock out clients already in the table).
  Entry* find(uint32_t ip, bool create);
  bool locked(const Entry& e, uint64_t now) const { return now < e.lockedUntil; }

  const hal::IClock& clock_;
  Entry entries_[32];
  Entry overflow_;
};

// `host` is the Host header (may carry ":port"). Allowed: the device IP, or
// "<hostname>" / "<hostname>.local" (case-insensitive).
bool hostAllowed(const char* host, const char* deviceIp, const char* hostname);

// For state-changing requests: if an Origin (or else Referer) header is present its
// host must pass hostAllowed(). Requests with neither (non-browser clients) pass;
// browsers always send Origin on cross-site POSTs.
bool originAllowed(const char* origin, const char* referer, const char* deviceIp, const char* hostname);

}  // namespace auth
