// Tests for dns::decidePolicy (lib/core/dns/query_policy.h): the order in which bans,
// DNS rewrites, the blocking pause and the lists apply, and the device's own lookups.
// Security-relevant: a wrong order would let a banned client through or block the
// board's own update and NTP lookups.

#include <unity.h>

#include <cstring>
#include <string>
#include <vector>

#include "dns/query_policy.h"
#include "fakes/dns_builder.h"

using dns::PolicyAction;

class FakeSources final : public dns::IPolicySources {
 public:
  bool banned(uint32_t) override {
    calls.push_back("banned");
    return isBanned;
  }
  bool rewrite(const dns::Query&, dns::RewriteAnswer&) override {
    calls.push_back("rewrite");
    return hasRewrite;
  }
  bool blockingOn() override {
    calls.push_back("blockingOn");
    return !paused;
  }
  bool listed(const dns::Query&) override {
    calls.push_back("listed");
    return isListed;
  }
  void record(uint32_t, bool blocked) override { recorded.push_back(blocked); }

  bool isBanned = false, hasRewrite = false, paused = false, isListed = false;
  std::vector<std::string> calls;
  std::vector<bool> recorded;
};

static FakeSources src;

void setUp() {
  src = FakeSources{};
}
void tearDown() {}

static uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {  // network byte order
  const uint8_t bytes[4] = {a, b, c, d};
  uint32_t v;
  memcpy(&v, bytes, 4);
  return v;
}

static PolicyAction decide(uint32_t client) {
  testdns::Bytes pkt = testdns::makeQuery("ads.example.com", dns::kTypeA);
  dns::Query q;
  dns::parseQuery(pkt.data(), pkt.size(), q);
  dns::RewriteAnswer rw;
  return dns::decidePolicy(src, q, client, rw);
}

static const uint32_t kLan = ip(192, 168, 68, 50);

static void test_listed_name_is_blocked_and_counted() {
  src.isListed = true;
  TEST_ASSERT_EQUAL(static_cast<int>(PolicyAction::kBlock), static_cast<int>(decide(kLan)));
  TEST_ASSERT_EQUAL(1, src.recorded.size());
  TEST_ASSERT_TRUE(src.recorded[0]);
}

static void test_unlisted_name_is_forwarded() {
  TEST_ASSERT_EQUAL(static_cast<int>(PolicyAction::kForward), static_cast<int>(decide(kLan)));
  TEST_ASSERT_FALSE(src.recorded[0]);
}

static void test_ban_beats_everything() {
  src.isBanned = src.hasRewrite = src.isListed = true;
  src.paused = true;
  TEST_ASSERT_EQUAL(static_cast<int>(PolicyAction::kBan), static_cast<int>(decide(kLan)));
  TEST_ASSERT_EQUAL(1, src.calls.size());  // nothing else consulted
}

static void test_rewrite_beats_the_lists_and_applies_while_paused() {
  src.hasRewrite = src.isListed = true;
  TEST_ASSERT_EQUAL(static_cast<int>(PolicyAction::kRewrite), static_cast<int>(decide(kLan)));
  src.paused = true;
  TEST_ASSERT_EQUAL(static_cast<int>(PolicyAction::kRewrite), static_cast<int>(decide(kLan)));
  for (const std::string& c : src.calls) TEST_ASSERT_TRUE(c != "listed");
}

static void test_pause_lets_listed_names_through() {
  src.isListed = true;
  src.paused = true;
  TEST_ASSERT_EQUAL(static_cast<int>(PolicyAction::kForward), static_cast<int>(decide(kLan)));
  TEST_ASSERT_FALSE(src.recorded[0]);
}

static void test_the_devices_own_lookups_skip_everything() {
  // The board's own lookups (NTP, blocklist download, upstream test) must never be
  // blocked, banned or rewritten, whatever a list contains.
  src.isBanned = src.hasRewrite = src.isListed = true;
  TEST_ASSERT_EQUAL(static_cast<int>(PolicyAction::kForward), static_cast<int>(decide(ip(127, 0, 0, 1))));
  TEST_ASSERT_EQUAL(static_cast<int>(PolicyAction::kForward), static_cast<int>(decide(ip(127, 9, 9, 9))));
  TEST_ASSERT_EQUAL(0, src.calls.size());
  TEST_ASSERT_EQUAL(0, src.recorded.size());
  // ...but only loopback: 128.x and a LAN address ending in 127 are ordinary clients.
  TEST_ASSERT_EQUAL(static_cast<int>(PolicyAction::kBan), static_cast<int>(decide(ip(192, 168, 1, 127))));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_listed_name_is_blocked_and_counted);
  RUN_TEST(test_unlisted_name_is_forwarded);
  RUN_TEST(test_ban_beats_everything);
  RUN_TEST(test_rewrite_beats_the_lists_and_applies_while_paused);
  RUN_TEST(test_pause_lets_listed_names_through);
  RUN_TEST(test_the_devices_own_lookups_skip_everything);
  return UNITY_END();
}
