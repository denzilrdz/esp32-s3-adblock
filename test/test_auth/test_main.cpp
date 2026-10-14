// Tests for lib/core/auth: hashed password storage, forced change of the public
// placeholder password, login lockout with backoff, and Host/Origin checks.

#include <unity.h>

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

static void test_placeholder_password_forces_a_change() {
  auth::PasswordStore s(kv, fakeRandom, "admin", auth::kPlaceholderPassword);
  TEST_ASSERT_TRUE(s.mustChange());
  TEST_ASSERT_TRUE(s.verify("admin", auth::kPlaceholderPassword));  // can log in to change it
  const char* why = nullptr;
  TEST_ASSERT_FALSE(s.change(auth::kPlaceholderPassword, "short", &why));
  TEST_ASSERT_EQUAL_STRING("new password must be at least 10 characters", why);
  TEST_ASSERT_FALSE(s.change(auth::kPlaceholderPassword, auth::kPlaceholderPassword, &why));
  TEST_ASSERT_TRUE(s.change(auth::kPlaceholderPassword, "correct horse battery", &why));
  TEST_ASSERT_FALSE(s.mustChange());
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

static void test_host_header_checks_block_dns_rebinding() {
  TEST_ASSERT_TRUE(auth::hostAllowed("192.168.1.50", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_TRUE(auth::hostAllowed("192.168.1.50:80", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_TRUE(auth::hostAllowed("S3AdBlock.local", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_TRUE(auth::hostAllowed("s3adblock", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("evil.example", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("s3adblock.local.evil.example", "192.168.1.50", "s3adblock"));
  TEST_ASSERT_FALSE(auth::hostAllowed("192.168.1.500", "192.168.1.50", "s3adblock"));
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
  TEST_ASSERT_FALSE(auth::originAllowed(nullptr, "http://evil.example/?x=http://192.168.1.50", ip, "s3adblock"));
  // Origin wins over Referer when both are present.
  TEST_ASSERT_FALSE(auth::originAllowed("http://evil.example", "http://192.168.1.50/", ip, "s3adblock"));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_placeholder_password_forces_a_change);
  RUN_TEST(test_changed_password_is_hashed_and_survives_reboot);
  RUN_TEST(test_old_password_stops_working_after_change_even_if_cached);
  RUN_TEST(test_salts_differ_between_changes);
  RUN_TEST(test_login_guard_locks_out_with_backoff);
  RUN_TEST(test_host_header_checks_block_dns_rebinding);
  RUN_TEST(test_origin_checks_block_cross_site_requests);
  return UNITY_END();
}
