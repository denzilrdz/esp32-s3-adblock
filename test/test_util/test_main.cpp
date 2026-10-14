// Tests for lib/core/util: CRC-32, byte helpers, civil time conversion.

#include <unity.h>

#include <cstring>

#include "util/bytes.h"
#include "util/civil_time.h"
#include "util/crc32.h"

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

static void test_crc32_empty_is_zero() { TEST_ASSERT_EQUAL_HEX32(0, util::crc32(nullptr, 0)); }

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

static void test_civil_epoch_and_ist_offset() {
  util::CivilTime t = util::civilFromUnix(0, 0);
  TEST_ASSERT_EQUAL(1970, t.year);
  TEST_ASSERT_EQUAL(1, t.month);
  TEST_ASSERT_EQUAL(1, t.day);
  // 2026-10-14 20:30:00 UTC == 2026-10-15 02:00:00 IST
  const int64_t unix = 1792009800;
  t = util::civilFromUnix(unix, 19800);
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

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_crc32_matches_zlib_check_value);
  RUN_TEST(test_crc32_incremental_equals_one_shot);
  RUN_TEST(test_crc32_empty_is_zero);
  RUN_TEST(test_byte_helpers_round_trip);
  RUN_TEST(test_civil_epoch_and_ist_offset);
  RUN_TEST(test_civil_round_trip_including_leap_day);
  return UNITY_END();
}
