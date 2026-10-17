// Tests for lib/core/auth: hashed password storage, forced change of the public
// placeholder password, login lockout with backoff, and Host/Origin checks.

#include <unity.h>

#include <cstring>
#include <string>

#include "auth/auth.h"
#include "fakes/fake_clock.h"
#include "fakes/fake_random.h"
#include "fakes/mem_kv_store.h"

static MemKvStore kv;
static FakeRandom fakeRandom;
static FakeClock fakeClock;

void setUp() {
  kv = MemKvStore{};
  fakeRandom = FakeRandom{};
  fakeClock = FakeClock{};
}
void tearDown() {}

static void test_placeholder_password_never_authenticates() {
  // The placeholder is public (it's in secrets.example.h): anyone on the LAN could use
  // it to claim the device. Only the serial-console setup code may set the password.
  auth::PasswordStore s(kv, fakeRandom, "admin", auth::kPlaceholderPassword);
  TEST_ASSERT_TRUE(s.mustChange());
  TEST_ASSERT_EQUAL(12, strlen(s.setupCode()));
  TEST_ASSERT_FALSE(s.verify("admin", auth::kPlaceholderPassword));
  TEST_ASSERT_FALSE(s.verify("admin", ""));
  const char* why = nullptr;
  TEST_ASSERT_FALSE(s.change(auth::kPlaceholderPassword, "correct horse battery", &why));
  TEST_ASSERT_EQUAL_STRING("current password is wrong", why);
  const std::string code = s.setupCode();
  TEST_ASSERT_TRUE(s.verify("admin", code.c_str()));
  TEST_ASSERT_FALSE(s.change(code.c_str(), "short", &why));
  TEST_ASSERT_EQUAL_STRING("new password must be at least 10 characters", why);
  TEST_ASSERT_TRUE(s.change(code.c_str(), "correct horse battery", &why));
  TEST_ASSERT_FALSE(s.mustChange());
  TEST_ASSERT_EQUAL_STRING("", s.setupCode());
  TEST_ASSERT_FALSE(s.verify("admin", code.c_str()));  // the code is single-use
}

static void test_missing_or_weak_default_also_needs_setup_code() {
  auth::PasswordStore none(kv, fakeRandom, "admin", "");
  TEST_ASSERT_TRUE(none.mustChange());
  TEST_ASSERT_FALSE(none.verify("admin", ""));
  auth::PasswordStore weak(kv, fakeRandom, "admin", "admin123");
  TEST_ASSERT_TRUE(weak.mustChange());
  TEST_ASSERT_FALSE(weak.verify("admin", "admin123"));
  auth::PasswordStore null(kv, fakeRandom, nullptr, nullptr);
  TEST_ASSERT_TRUE(null.mustChange());
  TEST_ASSERT_EQUAL_STRING("admin", null.user());
}

static void test_changed_password_is_hashed_and_survives_reboot() {
  {
    auth::PasswordStore s(kv, fakeRandom, "admin", "initial-secret-123");
    TEST_ASSERT_FALSE(s.mustChange());  // a real secrets.h password is accepted as-is
    TEST_ASSERT_TRUE(s.change("initial-secret-123", "a much better passphrase", nullptr));
  }
  uint8_t rec[64];
  size_t len = 0;
  TEST_ASSERT_TRUE(kv.getBlob(auth::PasswordStore::kKey, rec, sizeof(rec), len));
  TEST_ASSERT_EQUAL(52, len);
  const std::string stored(reinterpret_cast<char*>(rec), len);
  TEST_ASSERT_TRUE(stored.find("better") == std::string::npos);  // never stored in clear

  auth::PasswordStore rebooted(kv, fakeRandom, "admin", "initial-secret-123");
  TEST_ASSERT_TRUE(rebooted.hasStoredPassword());
  TEST_ASSERT_TRUE(rebooted.verify("admin", "a much better passphrase"));
  TEST_ASSERT_FALSE(rebooted.verify("admin", "initial-secret-123"));  // secrets.h no longer works
  TEST_ASSERT_FALSE(rebooted.verify("root", "a much better passphrase"));
}

static void test_old_password_stops_working_after_change_even_if_cached() {
  auth::PasswordStore s(kv, fakeRandom, "admin", "initial-secret-123");
  TEST_ASSERT_TRUE(s.verify("admin", "initial-secret-123"));  // now cached
  TEST_ASSERT_TRUE(s.change("initial-secret-123", "another-strong-one", nullptr));
  TEST_ASSERT_FALSE(s.verify("admin", "initial-secret-123"));
  TEST_ASSERT_TRUE(s.verify("admin", "another-strong-one"));
  const char* why = nullptr;
  TEST_ASSERT_FALSE(s.change("wrong-current-pass", "yet-another-password", &why));
  TEST_ASSERT_EQUAL_STRING("current password is wrong", why);
}

static void test_salts_differ_between_changes() {
  auth::PasswordStore s(kv, fakeRandom, "admin", "initial-secret-123");
  s.change("initial-secret-123", "same-new-password", nullptr);
  uint8_t a[64], b[64];
  size_t la, lb;
  kv.getBlob(auth::PasswordStore::kKey, a, sizeof(a), la);
  s.change("same-new-password", "other-new-password", nullptr);
  s.change("other-new-password", "same-new-password", nullptr);
  kv.getBlob(auth::PasswordStore::kKey, b, sizeof(b), lb);
  TEST_ASSERT_FALSE(memcmp(a, b, 16) == 0);  // same password, new salt -> new record
}

static void test_login_guard_locks_out_with_backoff() {
  auth::LoginGuard g(fakeClock);
  const uint32_t ip = 0x0A000005;
  for (int i = 0; i < 4; i++) {
    TEST_ASSERT_TRUE(g.allowed(ip));
    g.onFailure(ip);
  }
  TEST_ASSERT_TRUE(g.allowed(ip));
  g.onFailure(ip);  // 5th failure: locked for 30 s
  TEST_ASSERT_FALSE(g.allowed(ip));
  TEST_ASSERT_EQUAL_UINT32(30, g.retryAfterSeconds(ip));
  TEST_ASSERT_TRUE(g.allowed(0x0A000006));  // other clients unaffected
  fakeClock.advanceSeconds(30);
  TEST_ASSERT_TRUE(g.allowed(ip));
  g.onFailure(ip);  // next failure doubles the lock
  TEST_ASSERT_EQUAL_UINT32(60, g.retryAfterSeconds(ip));
  for (int i = 0; i < 10; i++) {
    fakeClock.advanceSeconds(400);
    g.onFailure(ip);
  }
  TEST_ASSERT_EQUAL_UINT32(300, g.retryAfterSeconds(ip));  // capped at 5 min
  fakeClock.advanceSeconds(300);
  g.onSuccess(ip);
  TEST_ASSERT_TRUE(g.allowed(ip));
  g.onFailure(ip);
  TEST_ASSERT_TRUE(g.allowed(ip));  // counter reset by the success
}

static void test_locked_clients_cannot_be_evicted_by_others() {
  auth::LoginGuard g(fakeClock);
  const uint32_t attacker = 0x0A000063;
  for (int i = 0; i < 5; i++) g.onFailure(attacker);  // locked 30 s
  // 40 other addresses fail once each: more than the table holds, so entries are
  // evicted - but never the locked attacker.
  for (uint32_t k = 1; k <= 40; k++) g.onFailure(0x0A000100 + k);
  TEST_ASSERT_FALSE(g.allowed(attacker));
  TEST_ASSERT_TRUE(g.retryAfterSeconds(attacker) > 0);
}

static void test_one_client_cannot_lock_out_another() {
  auth::LoginGuard g(fakeClock);
  const uint32_t owner = 0x0A000002;
  for (int i = 0; i < 200; i++) g.onFailure(0x0A000063);  // attacker hammers from its address
  TEST_ASSERT_TRUE(g.allowed(owner));
  // An attacker controlling 33+ addresses can fill the table with locks; newcomers
  // then share one overflow entry, which the attacker can lock too (residual risk,
  // documented in ARCHITECTURE.md §9). A success never unlocks that shared entry.
  for (uint32_t k = 0; k < 40; k++)
    for (int i = 0; i < 5; i++) g.onFailure(0x0A000200 + k);
  TEST_ASSERT_FALSE(g.allowed(0x0A000300));  // newcomer: overflow entry is locked
  g.onSuccess(0x0A000300);
  TEST_ASSERT_FALSE(g.allowed(0x0A000300));
}

static void test_host_header_checks_block_dns_rebinding() {
  TEST_ASSERT_TRUE(auth::hostAllowed("192.168.1.50", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_TRUE(auth::hostAllowed("192.168.1.50:80", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_TRUE(auth::hostAllowed("S3AdBlock.local", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_TRUE(auth::hostAllowed("s3adblock", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("evil.example", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("s3adblock.local.evil.example", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("192.168.1.500", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("192.168.1.50:evil.example", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("192.168.1.50:", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("192.168.1.50:80:80", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("[::1]:80", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed(nullptr, "192.168.1.50", "s3adblock"));
}

static void test_origin_checks_block_cross_site_requests() {
  const char* ip = "192.168.1.50";
  TEST_ASSERT_TRUE(auth::originAllowed("http://192.168.1.50", nullptr, ip, "s3adblock"));
  TEST_ASSERT_TRUE(auth::originAllowed(nullptr, "http://s3adblock.local/settings", ip, "s3adblock"));
  TEST_ASSERT_TRUE(auth::originAllowed(nullptr, nullptr, ip, "s3adblock"));  // curl etc.
  TEST_ASSERT_FALSE(auth::originAllowed("https://evil.example", nullptr, ip, "s3adblock"));
  TEST_ASSERT_FALSE(auth::originAllowed("null", nullptr, ip, "s3adblock"));
  TEST_ASSERT_FALSE(auth::originAllowed("http://s3adblock.local@evil.example", nullptr, ip, "s3adblock"));
  TEST_ASSERT_FALSE(
      auth::originAllowed(nullptr, "http://evil.example/?x=http://192.168.1.50", ip, "s3adblock"));
  // Origin wins over Referer when both are present.
  TEST_ASSERT_FALSE(auth::originAllowed("http://evil.example", "http://192.168.1.50/", ip, "s3adblock"));
}

static void test_url_origin_for_the_dashboard_csp() {
  char o[64];
  TEST_ASSERT_TRUE(auth::urlOrigin("https://denzilrdz.github.io/esp32-s3-adblock/", o, sizeof(o)));
  TEST_ASSERT_EQUAL_STRING("https://denzilrdz.github.io", o);
  TEST_ASSERT_TRUE(auth::urlOrigin("http://192.168.0.101:8765/x/update.json", o, sizeof(o)));
  TEST_ASSERT_EQUAL_STRING("http://192.168.0.101:8765", o);
  TEST_ASSERT_TRUE(auth::urlOrigin("HTTPS://Example.ORG", o, sizeof(o)));  // no path, mixed case
  TEST_ASSERT_EQUAL_STRING("https://example.org", o);
  // The result goes into a Content-Security-Policy header: anything that is not a
  // plain http(s)://host[:port] must be refused, never passed through.
  const char* bad[] = {"",
                       "ftp://example.org/",
                       "//example.org/",
                       "https://",
                       "https:///path",
                       "https://exa mple.org/",
                       "https://example.org;script-src *",
                       "https://example.org'/",
                       "https://user@example.org/",
                       "https://example.org:/",
                       "https://example.org:99999/",
                       "javascript:alert(1)"};
  for (const char* u : bad) TEST_ASSERT_FALSE_MESSAGE(auth::urlOrigin(u, o, sizeof(o)), u);
  char tiny[12];
  TEST_ASSERT_FALSE(auth::urlOrigin("https://denzilrdz.github.io/", tiny, sizeof(tiny)));  // too long
  TEST_ASSERT_FALSE(auth::urlOrigin(nullptr, o, sizeof(o)));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_placeholder_password_never_authenticates);
  RUN_TEST(test_missing_or_weak_default_also_needs_setup_code);
  RUN_TEST(test_changed_password_is_hashed_and_survives_reboot);
  RUN_TEST(test_old_password_stops_working_after_change_even_if_cached);
  RUN_TEST(test_salts_differ_between_changes);
  RUN_TEST(test_login_guard_locks_out_with_backoff);
  RUN_TEST(test_locked_clients_cannot_be_evicted_by_others);
  RUN_TEST(test_one_client_cannot_lock_out_another);
  RUN_TEST(test_host_header_checks_block_dns_rebinding);
  RUN_TEST(test_origin_checks_block_cross_site_requests);
  RUN_TEST(test_url_origin_for_the_dashboard_csp);
  return UNITY_END();
}
