// Tests for lib/core/clients: the persistent ban list (/banned.txt) and the blocking
// pause timer used by app::ClientTable.

#include <unity.h>

#include <cstring>
#include <string>

#include "clients/ban_list.h"
#include "clients/pause_timer.h"

using clients::BanList;
using clients::PauseTimer;

void setUp() {}
void tearDown() {}

// IPv4 in network byte order, as lwIP and Arduino's IPAddress store it.
static uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  const uint8_t bytes[4] = {a, b, c, d};
  uint32_t v;
  memcpy(&v, bytes, 4);
  return v;
}

static std::string text(const BanList& b) {
  char buf[BanList::kMaxTextBytes];
  const size_t n = b.serialize(buf, sizeof(buf));
  return std::string(buf, n);
}

static void test_add_remove_contains() {
  BanList b;
  TEST_ASSERT_FALSE(b.contains(ip(192, 168, 0, 101)));
  TEST_ASSERT_TRUE(b.add(ip(192, 168, 0, 101)));
  TEST_ASSERT_TRUE(b.add(ip(192, 168, 0, 101)));  // already there: still banned, no duplicate
  TEST_ASSERT_EQUAL(1, b.size());
  TEST_ASSERT_TRUE(b.contains(ip(192, 168, 0, 101)));
  TEST_ASSERT_FALSE(b.contains(ip(192, 168, 0, 102)));
  TEST_ASSERT_TRUE(b.remove(ip(192, 168, 0, 101)));
  TEST_ASSERT_FALSE(b.remove(ip(192, 168, 0, 101)));
  TEST_ASSERT_EQUAL(0, b.size());
}

static void test_full_list_refuses_new_bans() {
  BanList b;
  for (int i = 0; i < BanList::kMax; i++) TEST_ASSERT_TRUE(b.add(ip(10, 0, 0, static_cast<uint8_t>(i + 1))));
  TEST_ASSERT_FALSE(b.add(ip(10, 0, 1, 1)));  // the caller must say "ban list full"
  TEST_ASSERT_FALSE(b.contains(ip(10, 0, 1, 1)));
  TEST_ASSERT_TRUE(b.add(ip(10, 0, 0, 1)));  // re-banning an existing entry still works
  TEST_ASSERT_EQUAL(BanList::kMax, b.size());
}

static void test_text_format_round_trip() {
  BanList b;
  b.add(ip(192, 168, 0, 101));
  b.add(ip(10, 1, 2, 3));
  TEST_ASSERT_EQUAL_STRING("192.168.0.101\n10.1.2.3\n", text(b).c_str());
  BanList back;
  const std::string t = text(b);
  back.parse(t.data(), t.size());
  TEST_ASSERT_EQUAL(2, back.size());
  TEST_ASSERT_TRUE(back.contains(ip(192, 168, 0, 101)));
  TEST_ASSERT_TRUE(back.contains(ip(10, 1, 2, 3)));
}

static void test_parse_skips_bad_lines_and_duplicates() {
  const char* file =
      "192.168.0.5\r\n"
      "  192.168.0.6  \n"
      "\n"
      "not an ip\n"
      "300.1.1.1\n"
      "1.2.3\n"
      "1.2.3.4.5\n"
      "192.168.0.5\n"  // duplicate
      "192.168.0.7";   // no final newline
  BanList b;
  b.parse(file, strlen(file));
  TEST_ASSERT_EQUAL(3, b.size());
  TEST_ASSERT_TRUE(b.contains(ip(192, 168, 0, 5)));
  TEST_ASSERT_TRUE(b.contains(ip(192, 168, 0, 6)));
  TEST_ASSERT_TRUE(b.contains(ip(192, 168, 0, 7)));
}

static void test_parse_stops_at_the_limit() {
  std::string file;
  for (int i = 1; i <= BanList::kMax + 5; i++) file += "10.0.0." + std::to_string(i) + "\n";
  BanList b;
  b.parse(file.data(), file.size());
  TEST_ASSERT_EQUAL(BanList::kMax, b.size());
}

static void test_bans_survive_independently_of_seen_clients() {
  // Found while testing v0.2.1: after a restart, the bans were rebuilt from the clients
  // seen since boot whenever any ban changed, so a banned device that hadn't sent a
  // query yet was silently unbanned. The list is now the only source of truth.
  BanList afterReboot;
  const char* file = "192.168.0.50\n";  // banned before the restart, not seen since
  afterReboot.parse(file, strlen(file));
  afterReboot.add(ip(192, 168, 0, 60));  // ban another device
  TEST_ASSERT_EQUAL_STRING("192.168.0.50\n192.168.0.60\n", text(afterReboot).c_str());
}

static void test_serialize_never_overruns() {
  BanList b;
  for (int i = 0; i < BanList::kMax; i++) b.add(ip(255, 255, 255, static_cast<uint8_t>(i)));
  char small[20];
  const size_t n = b.serialize(small, sizeof(small));
  TEST_ASSERT_TRUE(n <= sizeof(small));
  TEST_ASSERT_EQUAL_STRING_LEN("255.255.255.0\n", small, 14);  // only whole lines
  char full[BanList::kMaxTextBytes];                           // the worst case fits: 10 x 14 + 22 x 15 chars
  TEST_ASSERT_EQUAL(470, b.serialize(full, sizeof(full)));
}

static void test_pause_for_a_time_then_resume_on_its_own() {
  PauseTimer p;
  const uint64_t t0 = 5000;
  TEST_ASSERT_TRUE(p.blockingOn(t0));
  p.pause(t0, 300);  // "Pause 5 min"
  TEST_ASSERT_FALSE(p.blockingOn(t0));
  TEST_ASSERT_EQUAL_UINT32(300, p.resumeInSeconds(t0));
  TEST_ASSERT_EQUAL_UINT32(120, p.resumeInSeconds(t0 + 180000));
  TEST_ASSERT_FALSE(p.blockingOn(t0 + 299999));
  TEST_ASSERT_TRUE(p.blockingOn(t0 + 300000));  // back on by itself
  TEST_ASSERT_EQUAL_UINT32(0, p.resumeInSeconds(t0 + 300000));
}

static void test_pause_until_resumed() {
  PauseTimer p;
  p.pause(1000, 0);
  TEST_ASSERT_FALSE(p.blockingOn(1000 + 30ULL * 24 * 3600 * 1000));  // a month later: still paused
  TEST_ASSERT_EQUAL_UINT32(0, p.resumeInSeconds(5000));              // no countdown
  p.resume();
  TEST_ASSERT_TRUE(p.blockingOn(5000));
}

static void test_resume_early_and_pause_again() {
  PauseTimer p;
  p.pause(0, 3600);
  p.resume();
  TEST_ASSERT_TRUE(p.blockingOn(1000));
  p.pause(2000, 60);  // a new pause replaces the old one
  TEST_ASSERT_FALSE(p.blockingOn(2000));
  TEST_ASSERT_TRUE(p.blockingOn(62000));
}

static void test_long_uptime_has_no_wraparound() {
  // millis() wraps after 49.7 days; the timer works on 64-bit milliseconds.
  PauseTimer p;
  const uint64_t t = 0xFFFFFFF0ULL;  // just before a 32-bit wrap
  p.pause(t, 60);
  TEST_ASSERT_FALSE(p.blockingOn(t + 1000));
  TEST_ASSERT_EQUAL_UINT32(59, p.resumeInSeconds(t + 1000));
  TEST_ASSERT_TRUE(p.blockingOn(t + 60000));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_add_remove_contains);
  RUN_TEST(test_full_list_refuses_new_bans);
  RUN_TEST(test_text_format_round_trip);
  RUN_TEST(test_parse_skips_bad_lines_and_duplicates);
  RUN_TEST(test_parse_stops_at_the_limit);
  RUN_TEST(test_bans_survive_independently_of_seen_clients);
  RUN_TEST(test_serialize_never_overruns);
  RUN_TEST(test_pause_for_a_time_then_resume_on_its_own);
  RUN_TEST(test_pause_until_resumed);
  RUN_TEST(test_resume_early_and_pause_again);
  RUN_TEST(test_long_uptime_has_no_wraparound);
  return UNITY_END();
}
