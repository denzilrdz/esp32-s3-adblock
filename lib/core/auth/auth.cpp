#include "auth/auth.h"

#include <cstring>

#include "util/bytes.h"

namespace auth {

namespace {

// Stored record: salt(16) | hash(32) | iterations(4, BE)
constexpr size_t kRecordSize = 16 + util::kSha256Size + 4;

char lower(char c) {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}

bool equalsCi(const char* a, size_t aLen, const char* b) {
  if (strlen(b) != aLen) return false;
  for (size_t i = 0; i < aLen; i++)
    if (lower(a[i]) != lower(b[i])) return false;
  return true;
}

}  // namespace

PasswordStore::PasswordStore(hal::IKeyValueStore& kv, hal::IRandom& random, const char* defaultUser,
                             const char* defaultPassword)
    : kv_(kv),
      random_(random),
      user_(defaultUser ? defaultUser : "admin"),
      defaultPassword_(defaultPassword) {
  uint8_t rec[kRecordSize];
  size_t len = 0;
  if (kv_.getBlob(kKey, rec, sizeof(rec), len) && len == kRecordSize &&
      util::readU32Be(rec + 16 + util::kSha256Size) == kIterations) {
    memcpy(salt_, rec, 16);
    memcpy(hash_, rec + 16, util::kSha256Size);
    stored_ = true;
  }
  if (mustChange()) {
    // 12 characters from an unambiguous alphabet (no 0/O/1/l): ~60 bits.
    static const char kAlphabet[] = "23456789abcdefghjkmnpqrstuvwxyz";
    for (int i = 0; i < 12; i++) setupCode_[i] = kAlphabet[random_.next32() % (sizeof(kAlphabet) - 1)];
    setupCode_[12] = 0;
  }
}

bool PasswordStore::mustChange() const {
  return !stored_ && (!defaultPassword_ || strcmp(defaultPassword_, kPlaceholderPassword) == 0 ||
                      strlen(defaultPassword_) < kMinPasswordLength);
}

void PasswordStore::deriveKey(const char* password, const uint8_t* salt,
                              uint8_t out[util::kSha256Size]) const {
  util::pbkdf2Sha256(reinterpret_cast<const uint8_t*>(password), strlen(password), salt, 16, kIterations, out,
                     util::kSha256Size);
}

void PasswordStore::cacheCredentials(const char* user, const char* password) {
  util::Sha256 s;
  s.update(reinterpret_cast<const uint8_t*>(user), strlen(user));
  s.update(reinterpret_cast<const uint8_t*>(":"), 1);
  s.update(reinterpret_cast<const uint8_t*>(password), strlen(password));
  s.finish(cache_);
  haveCache_ = true;
}

bool PasswordStore::cachedMatch(const char* user, const char* password) const {
  if (!haveCache_) return false;
  uint8_t h[util::kSha256Size];
  util::Sha256 s;
  s.update(reinterpret_cast<const uint8_t*>(user), strlen(user));
  s.update(reinterpret_cast<const uint8_t*>(":"), 1);
  s.update(reinterpret_cast<const uint8_t*>(password), strlen(password));
  s.finish(h);
  return util::constantTimeEqual(h, cache_, sizeof(h));
}

bool PasswordStore::verify(const char* user, const char* password) {
  if (!user || !password || strcmp(user, user_) != 0) return false;
  if (cachedMatch(user, password)) return true;
  bool ok;
  if (stored_) {
    uint8_t h[util::kSha256Size];
    deriveKey(password, salt_, h);
    ok = util::constantTimeEqual(h, hash_, sizeof(h));
  } else {
    // First boot. A strong secrets.h password works; a missing/weak/placeholder one
    // never does (it may be public) - only the serial-console setup code.
    const char* expected = mustChange() ? setupCode_ : defaultPassword_;
    uint8_t a[util::kSha256Size], b[util::kSha256Size];  // compare hashes: constant length
    util::sha256(reinterpret_cast<const uint8_t*>(password), strlen(password), a);
    util::sha256(reinterpret_cast<const uint8_t*>(expected), strlen(expected), b);
    ok = *expected && util::constantTimeEqual(a, b, sizeof(a));
  }
  if (ok) cacheCredentials(user, password);
  return ok;
}

bool PasswordStore::change(const char* current, const char* next, const char** why) {
  if (!current) current = "";
  if (!next) next = "";
  const char* reason = nullptr;
  const size_t n = strlen(next);
  if (!verify(user_, current))
    reason = "current password is wrong";
  else if (n < kMinPasswordLength)
    reason = "new password must be at least 10 characters";
  else if (n > kMaxPasswordLength)
    reason = "new password is too long (max 64)";
  else if (strcmp(next, kPlaceholderPassword) == 0)
    reason = "that is the public example password";
  else if (strcmp(next, current) == 0)
    reason = "new password must differ from the current one";
  if (reason) {
    if (why) *why = reason;
    return false;
  }
  uint8_t salt[16];
  for (int i = 0; i < 16; i += 4) util::writeU32Be(salt + i, random_.next32());
  uint8_t h[util::kSha256Size];
  deriveKey(next, salt, h);
  uint8_t rec[kRecordSize];
  memcpy(rec, salt, 16);
  memcpy(rec + 16, h, sizeof(h));
  util::writeU32Be(rec + 16 + util::kSha256Size, kIterations);
  if (!kv_.setBlob(kKey, rec, sizeof(rec))) {
    if (why) *why = "could not save (NVS error)";
    return false;
  }
  memcpy(salt_, salt, 16);
  memcpy(hash_, h, sizeof(h));
  stored_ = true;
  haveCache_ = false;  // old credentials must not keep working through the cache
  memset(setupCode_, 0, sizeof(setupCode_));
  return true;
}

LoginGuard::Entry* LoginGuard::find(uint32_t ip, bool create) {
  const uint64_t now = clock_.monotonicMs();
  Entry* victim = nullptr;
  for (Entry& e : entries_) {
    if (e.ip == ip && (e.failures || e.lockedUntil)) return &e;
    if (!locked(e, now) && (!victim || e.lastSeen < victim->lastSeen)) victim = &e;
  }
  if (!victim) return &overflow_;  // all slots locked: newcomers share one entry
  if (!create) return nullptr;
  *victim = Entry{};
  victim->ip = ip;
  return victim;
}

bool LoginGuard::allowed(uint32_t ip) {
  Entry* e = find(ip, false);
  return !e || !locked(*e, clock_.monotonicMs());
}

uint32_t LoginGuard::retryAfterSeconds(uint32_t ip) {
  const uint64_t now = clock_.monotonicMs();
  Entry* e = find(ip, false);
  return (!e || now >= e->lockedUntil) ? 0 : static_cast<uint32_t>((e->lockedUntil - now + 999) / 1000);
}

void LoginGuard::onFailure(uint32_t ip) {
  const uint64_t now = clock_.monotonicMs();
  Entry* e = find(ip, true);
  e->lastSeen = now;
  if (++e->failures < kFreeAttempts) return;
  e->lockMs = e->lockMs ? (e->lockMs * 2 > kMaxLockMs ? kMaxLockMs : e->lockMs * 2) : kBaseLockMs;
  e->lockedUntil = now + e->lockMs;
  e->failures = kFreeAttempts - 1;  // each further failure after the lock extends it
}

void LoginGuard::onSuccess(uint32_t ip) {
  Entry* e = find(ip, false);
  if (e && e != &overflow_) *e = Entry{};
}

bool hostAllowed(const char* host, const char* deviceIp, const char* hostname) {
  if (!host || !*host) return false;
  size_t len = strlen(host);
  const char* colon = strchr(host, ':');
  if (colon) {  // strip ":port"; the port must be 1-5 digits and nothing else
    const char* p = colon + 1;
    size_t digits = 0;
    while (p[digits] >= '0' && p[digits] <= '9') digits++;
    if (digits == 0 || digits > 5 || p[digits] != 0) return false;
    len = static_cast<size_t>(colon - host);
  }
  if (deviceIp && equalsCi(host, len, deviceIp)) return true;
  if (!hostname || !*hostname) return false;
  if (equalsCi(host, len, hostname)) return true;
  const size_t h = strlen(hostname);
  return len == h + 6 && equalsCi(host, h, hostname) && equalsCi(host + h, 6, ".local");
}

bool originAllowed(const char* origin, const char* referer, const char* deviceIp, const char* hostname) {
  const char* url = (origin && *origin) ? origin : ((referer && *referer) ? referer : nullptr);
  if (!url) return true;
  if (strcmp(url, "null") == 0) return false;  // sandboxed/opaque origin
  const char* p = strstr(url, "://");
  if (!p) return false;
  p += 3;
  char host[128];
  size_t i = 0;
  while (p[i] && p[i] != '/' && p[i] != '?' && p[i] != '#' && i < sizeof(host) - 1) {
    host[i] = p[i];
    i++;
  }
  host[i] = 0;
  if (strchr(host, '@')) return false;  // userinfo tricks
  return hostAllowed(host, deviceIp, hostname);
}

bool urlOrigin(const char* url, char* out, size_t cap) {
  if (!url || !out || cap == 0) return false;
  auto lower = [](char ch) { return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch; };
  auto startsWith = [&](const char* prefix) {
    for (size_t k = 0; prefix[k]; k++)
      if (lower(url[k]) != prefix[k]) return false;
    return true;
  };
  size_t i;
  if (startsWith("https://"))
    i = 8;
  else if (startsWith("http://"))
    i = 7;
  else
    return false;
  size_t hostLen = 0;
  for (; url[i] && url[i] != '/' && url[i] != ':'; i++, hostLen++) {
    const char ch = lower(url[i]);
    if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-')) return false;
  }
  if (hostLen == 0) return false;
  size_t end = i;
  if (url[i] == ':') {
    uint32_t port = 0;
    size_t digits = 0;
    for (i++; url[i] >= '0' && url[i] <= '9'; i++, digits++) {
      port = port * 10 + static_cast<uint32_t>(url[i] - '0');
      if (port > 65535) return false;
    }
    if (digits == 0 || port == 0) return false;
    end = i;
  }
  if (url[end] && url[end] != '/') return false;  // e.g. "host;..." or "host'x"
  if (end + 1 > cap) return false;
  for (size_t k = 0; k < end; k++) out[k] = lower(url[k]);
  out[end] = 0;
  return true;
}

}  // namespace auth
