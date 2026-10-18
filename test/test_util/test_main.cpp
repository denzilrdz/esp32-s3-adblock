// Tests for lib/core/util: CRC-32, byte helpers, civil time conversion, Wi-Fi scan list.

#include <unity.h>

#include <algorithm>
#include <cstring>
#include <string>

#include "util/bytes.h"
#include "util/civil_time.h"
#include "util/crc32.h"
#include "util/sha256.h"
#include "util/wifi_scan.h"

void setUp() {}
void tearDown() {}

static void test_crc32_matches_zlib_check_value() {
  const char* s = "123456789";  // standard CRC-32 check input
  TEST_ASSERT_EQUAL_HEX32(0xCBF43926u, util::crc32(reinterpret_cast<const uint8_t*>(s), 9));
}

static void test_crc32_incremental_equals_one_shot() {
  const char* s = "The quick brown fox jumps over the lazy dog";
  const auto* p = reinterpret_cast<const uint8_t*>(s);
  const size_t n = strlen(s);
  uint32_t c = util::crc32Update(0, p, 10);
  c = util::crc32Update(c, p + 10, n - 10);
  TEST_ASSERT_EQUAL_HEX32(util::crc32(p, n), c);
  TEST_ASSERT_EQUAL_HEX32(0x414FA339u, c);
}

static void test_crc32_empty_is_zero() {
  TEST_ASSERT_EQUAL_HEX32(0, util::crc32(nullptr, 0));
}

static void test_byte_helpers_round_trip() {
  uint8_t b[8];
  util::writeU16Be(b, 0xBEEF);
  TEST_ASSERT_EQUAL_HEX8(0xBE, b[0]);
  TEST_ASSERT_EQUAL_HEX16(0xBEEF, util::readU16Be(b));
  util::writeU32Be(b, 0x01020304);
  TEST_ASSERT_EQUAL_HEX8(0x01, b[0]);
  TEST_ASSERT_EQUAL_HEX32(0x01020304, util::readU32Be(b));
  util::writeU64Le(b, 0x1122334455667788ull);
  TEST_ASSERT_EQUAL_HEX8(0x88, b[0]);
  TEST_ASSERT_TRUE(util::readU64Le(b) == 0x1122334455667788ull);
}

static void test_civil_epoch_and_utc_offset() {
  util::CivilTime t = util::civilFromUnix(0, 0);
  TEST_ASSERT_EQUAL(1970, t.year);
  TEST_ASSERT_EQUAL(1, t.month);
  TEST_ASSERT_EQUAL(1, t.day);
  // 2026-10-14 20:30:00 UTC == 2026-10-15 02:00:00 at UTC+05:30
  const int64_t unixSeconds = 1792009800;
  t = util::civilFromUnix(unixSeconds, 19800);
  TEST_ASSERT_EQUAL(2026, t.year);
  TEST_ASSERT_EQUAL(10, t.month);
  TEST_ASSERT_EQUAL(15, t.day);
  TEST_ASSERT_EQUAL(2, t.hour);
  TEST_ASSERT_EQUAL(0, t.minute);
  TEST_ASSERT_EQUAL_UINT32(20261015u, t.dateKey());
}

static void test_civil_round_trip_including_leap_day() {
  util::CivilTime t;
  t.year = 2028;
  t.month = 2;
  t.day = 29;
  t.hour = 23;
  t.minute = 59;
  t.second = 59;
  const int64_t u = util::unixFromCivil(t, 19800);
  util::CivilTime back = util::civilFromUnix(u, 19800);
  TEST_ASSERT_EQUAL(2028, back.year);
  TEST_ASSERT_EQUAL(2, back.month);
  TEST_ASSERT_EQUAL(29, back.day);
  TEST_ASSERT_EQUAL(23, back.hour);
  TEST_ASSERT_EQUAL(59, back.second);
  back = util::civilFromUnix(u + 1, 19800);
  TEST_ASSERT_EQUAL(3, back.month);
  TEST_ASSERT_EQUAL(1, back.day);
}

static std::string hex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += d[p[i] >> 4];
    s += d[p[i] & 15];
  }
  return s;
}

// Expected values computed with Python's hashlib/hmac (and RFC 4231 / RFC 7914).
static void test_sha256_vectors() {
  uint8_t out[32];
  util::sha256(reinterpret_cast<const uint8_t*>("abc"), 3, out);
  TEST_ASSERT_EQUAL_STRING("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                           hex(out, 32).c_str());
  std::string a(1000, 'a');  // multi-block, streamed in odd chunks
  util::Sha256 s;
  for (size_t i = 0; i < a.size(); i += 7)
    s.update(reinterpret_cast<const uint8_t*>(a.data() + i), std::min<size_t>(7, a.size() - i));
  s.finish(out);
  TEST_ASSERT_EQUAL_STRING("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
                           hex(out, 32).c_str());
}

static void test_hmac_sha256_vectors() {
  uint8_t out[32];
  const char* msg = "what do ya want for nothing?";
  util::hmacSha256(reinterpret_cast<const uint8_t*>("Jefe"), 4, reinterpret_cast<const uint8_t*>(msg),
                   strlen(msg), out);
  TEST_ASSERT_EQUAL_STRING("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                           hex(out, 32).c_str());
  std::string longKey(100, 'k');  // key longer than the block size is hashed first
  util::hmacSha256(reinterpret_cast<const uint8_t*>(longKey.data()), longKey.size(),
                   reinterpret_cast<const uint8_t*>("msg"), 3, out);
  TEST_ASSERT_EQUAL_STRING("bd56a1782c2830e8abc6ed866a57a1230661e650b84c62f7ee3accc5fa5af491",
                           hex(out, 32).c_str());
}

static void test_pbkdf2_sha256_vectors() {
  uint8_t out[64];
  util::pbkdf2Sha256(reinterpret_cast<const uint8_t*>("passwd"), 6, reinterpret_cast<const uint8_t*>("salt"),
                     4, 1, out, 64);
  TEST_ASSERT_EQUAL_STRING(
      "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b8"
      "45b1e30bd509112041d3a19783",
      hex(out, 64).c_str());
  util::pbkdf2Sha256(reinterpret_cast<const uint8_t*>("password"), 8,
                     reinterpret_cast<const uint8_t*>("salt"), 4, 4096, out, 32);
  TEST_ASSERT_EQUAL_STRING("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
                           hex(out, 32).c_str());
}

static void test_constant_time_equal() {
  const uint8_t a[4] = {1, 2, 3, 4}, b[4] = {1, 2, 3, 5};
  TEST_ASSERT_TRUE(util::constantTimeEqual(a, a, 4));
  TEST_ASSERT_FALSE(util::constantTimeEqual(a, b, 4));
}

static util::ScanEntry scan(const char* ssid, int rssi, bool secured = true) {
  using util::WifiSecurity;
  util::ScanEntry e;
  strncpy(e.ssid, ssid, util::kMaxSsidLength);
  e.rssi = rssi;
  e.security = secured ? WifiSecurity::kPsk : WifiSecurity::kOpen;
  return e;
}

static void test_pick_networks_dedupes_sorts_and_drops_hidden() {
  const util::ScanEntry in[] = {scan("home", -70), scan("", -40),     scan("cafe", -50, false),
                                scan("home", -45), scan("work", -80), scan("cafe", -60)};
  util::ScanEntry out[8];
  const size_t n = util::pickNetworks(in, 6, out, 8);
  TEST_ASSERT_EQUAL(3, n);
  TEST_ASSERT_EQUAL_STRING("home", out[0].ssid);
  TEST_ASSERT_EQUAL(-45, out[0].rssi);  // the strongest access point for the name wins
  TEST_ASSERT_EQUAL_STRING("cafe", out[1].ssid);
  TEST_ASSERT_EQUAL(static_cast<int>(util::WifiSecurity::kOpen), static_cast<int>(out[1].security));
  TEST_ASSERT_EQUAL_STRING("work", out[2].ssid);
}

static void test_pick_networks_keeps_strongest_within_cap() {
  const util::ScanEntry in[] = {scan("a", -90), scan("b", -60), scan("c", -70), scan("d", -50),
                                scan("e", -60)};
  util::ScanEntry out[3];
  const size_t n = util::pickNetworks(in, 5, out, 3);
  TEST_ASSERT_EQUAL(3, n);
  TEST_ASSERT_EQUAL_STRING("d", out[0].ssid);
  TEST_ASSERT_EQUAL_STRING("b", out[1].ssid);  // ties keep scan order
  TEST_ASSERT_EQUAL_STRING("e", out[2].ssid);
  TEST_ASSERT_EQUAL(0, util::pickNetworks(in, 0, out, 3));
  TEST_ASSERT_EQUAL(0, util::pickNetworks(in, 5, out, 0));
}

static void test_signal_bars_thresholds() {
  TEST_ASSERT_EQUAL(4, util::signalBars(-30));
  TEST_ASSERT_EQUAL(4, util::signalBars(-55));
  TEST_ASSERT_EQUAL(3, util::signalBars(-56));
  TEST_ASSERT_EQUAL(3, util::signalBars(-67));
  TEST_ASSERT_EQUAL(2, util::signalBars(-75));
  TEST_ASSERT_EQUAL(1, util::signalBars(-76));
}

static int check(size_t ssidLen, const char* pw, util::WifiSecurity sec) {
  return static_cast<int>(util::checkCredentials(ssidLen, pw, strlen(pw), sec));
}

static void test_check_credentials() {
  using util::CredentialCheck;
  using util::WifiSecurity;
  const int ok = static_cast<int>(CredentialCheck::kOk),
            need = static_cast<int>(CredentialCheck::kNeedPassword),
            bad = static_cast<int>(CredentialCheck::kBadPassword),
            name = static_cast<int>(CredentialCheck::kBadName);
  const std::string hex64(64, 'a'), notHex = std::string(63, 'a') + "g", tooLong(65, 'a');
  // Regression: a secured network saved with an empty password never joined and took DNS down.
  TEST_ASSERT_EQUAL(need, check(4, "", WifiSecurity::kPsk));
  TEST_ASSERT_EQUAL(bad, check(4, "short", WifiSecurity::kPsk));
  TEST_ASSERT_EQUAL(ok, check(4, "12345678", WifiSecurity::kPsk));
  TEST_ASSERT_EQUAL(ok, check(4, std::string(63, 'x').c_str(), WifiSecurity::kPsk));
  TEST_ASSERT_EQUAL(ok, check(4, hex64.c_str(), WifiSecurity::kPsk));
  TEST_ASSERT_EQUAL(bad, check(4, notHex.c_str(), WifiSecurity::kPsk));
  TEST_ASSERT_EQUAL(bad, check(4, tooLong.c_str(), WifiSecurity::kPsk));
  TEST_ASSERT_EQUAL(ok, check(4, "", WifiSecurity::kOpen));
  TEST_ASSERT_EQUAL(ok, check(4, "ignored", WifiSecurity::kOpen));
  TEST_ASSERT_EQUAL(need, check(4, "", WifiSecurity::kOther));
  TEST_ASSERT_EQUAL(ok, check(4, "wep13", WifiSecurity::kOther));
  TEST_ASSERT_EQUAL(ok, check(4, "", WifiSecurity::kUnknown));
  TEST_ASSERT_EQUAL(bad, check(4, "short", WifiSecurity::kUnknown));
  TEST_ASSERT_EQUAL(ok, check(4, "longenough", WifiSecurity::kUnknown));
  TEST_ASSERT_EQUAL(name, check(0, "12345678", WifiSecurity::kPsk));
  TEST_ASSERT_EQUAL(name, check(33, "12345678", WifiSecurity::kPsk));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_crc32_matches_zlib_check_value);
  RUN_TEST(test_crc32_incremental_equals_one_shot);
  RUN_TEST(test_crc32_empty_is_zero);
  RUN_TEST(test_byte_helpers_round_trip);
  RUN_TEST(test_civil_epoch_and_utc_offset);
  RUN_TEST(test_civil_round_trip_including_leap_day);
  RUN_TEST(test_sha256_vectors);
  RUN_TEST(test_hmac_sha256_vectors);
  RUN_TEST(test_pbkdf2_sha256_vectors);
  RUN_TEST(test_constant_time_equal);
  RUN_TEST(test_pick_networks_dedupes_sorts_and_drops_hidden);
  RUN_TEST(test_pick_networks_keeps_strongest_within_cap);
  RUN_TEST(test_signal_bars_thresholds);
  RUN_TEST(test_check_credentials);
  return UNITY_END();
}
