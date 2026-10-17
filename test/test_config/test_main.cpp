// Tests for lib/core/config: defaults, validation of every field, NVS round trip,
// restart detection, and building the upstream chain from settings.

#include <unity.h>

#include <cstring>

#include "config/config.h"
#include "fakes/mem_kv_store.h"

using config::AppConfig;
using config::Provider;
using config::SetResult;

void setUp() {}
void tearDown() {}

static void assertSet(SetResult want, AppConfig& c, const char* k, const char* v) {
  TEST_ASSERT_EQUAL_MESSAGE(static_cast<int>(want), static_cast<int>(config::setField(c, k, v)), k);
}

static void test_defaults_match_the_design() {
  AppConfig c;
  TEST_ASSERT_EQUAL(static_cast<int>(Provider::kCloudflare), static_cast<int>(c.primary));
  TEST_ASSERT_EQUAL(static_cast<int>(Provider::kQuad9), static_cast<int>(c.secondary));
  TEST_ASSERT_TRUE(c.plainFallback);
  TEST_ASSERT_TRUE(c.padding);
  TEST_ASSERT_TRUE(c.firefoxCanary);
  TEST_ASSERT_FALSE(c.icloudRelay);
  TEST_ASSERT_EQUAL_STRING("UTC0", c.timezone);
  TEST_ASSERT_TRUE(config::validate(c, nullptr));
}

static void test_field_validation() {
  AppConfig c;
  assertSet(SetResult::kOk, c, "up_pri", "quad9");
  assertSet(SetResult::kInvalid, c, "up_pri", "google");
  assertSet(SetResult::kOk, c, "up_plain", "0");
  TEST_ASSERT_FALSE(c.plainFallback);
  assertSet(SetResult::kInvalid, c, "up_plain", "maybe");
  assertSet(SetResult::kOk, c, "blk_ttl", "3600");
  assertSet(SetResult::kInvalid, c, "blk_ttl", "3601");
  assertSet(SetResult::kInvalid, c, "blk_ttl", "-1");
  assertSet(SetResult::kInvalid, c, "blk_ttl", "10s");
  assertSet(SetResult::kOk, c, "up_cip", "94.140.14.14");
  assertSet(SetResult::kInvalid, c, "up_cip", "94.140.14.256");
  assertSet(SetResult::kInvalid, c, "up_cip", "94.140.14");
  assertSet(SetResult::kInvalid, c, "up_cip", "1.2.3.4.");
  assertSet(SetResult::kOk, c, "up_cname", "dns.adguard-dns.com");
  assertSet(SetResult::kInvalid, c, "up_cname", "Bad Name");
  assertSet(SetResult::kInvalid, c, "up_cname", "<script>.example");
  assertSet(SetResult::kOk, c, "tz", "UTC0");
  assertSet(SetResult::kInvalid, c, "tz", "UTC;rm -rf");
  assertSet(SetResult::kOk, c, "log", "3");
  assertSet(SetResult::kInvalid, c, "log", "9");
  assertSet(SetResult::kUnknownKey, c, "wifi_pass", "x");
}

// Values pasted into the dashboard often carry spaces (found on hardware: a pasted
// "192.0.2.1 " was rejected as "invalid value for up_cip").
static void test_values_are_trimmed() {
  AppConfig c;
  assertSet(SetResult::kOk, c, "up_cip", " 192.0.2.1 ");
  TEST_ASSERT_EQUAL_STRING("192.0.2.1", c.customIp);
  assertSet(SetResult::kOk, c, "up_cname", "\tcloudflare-dns.com\r\n");
  TEST_ASSERT_EQUAL_STRING("cloudflare-dns.com", c.customName);
  assertSet(SetResult::kOk, c, "up_pri", " custom");
  TEST_ASSERT_EQUAL(static_cast<int>(Provider::kCustom), static_cast<int>(c.primary));
  assertSet(SetResult::kOk, c, "blk_ttl", " 30 ");
  TEST_ASSERT_EQUAL(30u, c.blockedTtl);
  assertSet(SetResult::kOk, c, "up_cip", "   ");  // only spaces = cleared
  TEST_ASSERT_EQUAL_STRING("", c.customIp);
  assertSet(SetResult::kInvalid, c, "up_cip", "192.0 .2.1");  // inner spaces still invalid
  char longValue[200];
  memset(longValue, '1', sizeof(longValue) - 1);
  longValue[sizeof(longValue) - 1] = 0;
  assertSet(SetResult::kInvalid, c, "tz", longValue);
}

static void test_cross_field_validation() {
  AppConfig c;
  const char* why = nullptr;
  c.secondary = Provider::kCloudflare;
  TEST_ASSERT_FALSE(config::validate(c, &why));
  TEST_ASSERT_EQUAL_STRING("primary and secondary upstream must differ", why);
  c = AppConfig{};
  c.primary = Provider::kNone;
  TEST_ASSERT_FALSE(config::validate(c, &why));
  c = AppConfig{};
  c.secondary = Provider::kCustom;
  TEST_ASSERT_FALSE(config::validate(c, &why));
  TEST_ASSERT_EQUAL_STRING("custom upstream needs an IP and a TLS name", why);
  strcpy(c.customIp, "94.140.14.14");
  strcpy(c.customName, "dns.adguard-dns.com");
  TEST_ASSERT_TRUE(config::validate(c, &why));
}

static void test_round_trip_through_nvs() {
  MemKvStore kv;
  AppConfig c;
  config::setField(c, "up_pri", "quad9");
  config::setField(c, "up_sec", "cloudflare");
  config::setField(c, "blk_ttl", "42");
  config::setField(c, "icloud", "1");
  config::setField(c, "tz", "UTC0");
  TEST_ASSERT_TRUE(config::save(kv, c));
  AppConfig back;
  TEST_ASSERT_TRUE(config::load(kv, back));
  TEST_ASSERT_EQUAL(static_cast<int>(Provider::kQuad9), static_cast<int>(back.primary));
  TEST_ASSERT_EQUAL_UINT32(42, back.blockedTtl);
  TEST_ASSERT_TRUE(back.icloudRelay);
  TEST_ASSERT_EQUAL_STRING("UTC0", back.timezone);
  TEST_ASSERT_FALSE(config::requiresRestart(c, back));
}

static void test_load_handles_empty_future_and_corrupt_stores() {
  MemKvStore kv;
  AppConfig c;
  TEST_ASSERT_TRUE(config::load(kv, c));  // nothing saved: defaults
  TEST_ASSERT_EQUAL(static_cast<int>(Provider::kCloudflare), static_cast<int>(c.primary));
  kv.setU32("cfg_ver", 99);  // written by newer firmware
  TEST_ASSERT_FALSE(config::load(kv, c));
  kv.setU32("cfg_ver", 1);
  kv.setString("up_pri", "quad9");
  kv.setString("up_sec", "quad9");  // invalid combination -> defaults
  AppConfig d;
  TEST_ASSERT_TRUE(config::load(kv, d));
  TEST_ASSERT_EQUAL(static_cast<int>(Provider::kCloudflare), static_cast<int>(d.primary));
}

static void test_restart_needed_only_for_dns_settings() {
  AppConfig a, b;
  strcpy(b.timezone, "UTC0");
  b.logLevel = 3;
  TEST_ASSERT_FALSE(config::requiresRestart(a, b));
  b.plainFallback = false;
  TEST_ASSERT_TRUE(config::requiresRestart(a, b));
}

static void test_default_chain_order() {
  AppConfig c;
  config::Endpoint e[8];
  const size_t n = config::buildChain(c, e, 8);
  TEST_ASSERT_EQUAL(8, n);
  const char* names[] = {"cloudflare-dot", "cloudflare-dot-2", "quad9-dot",      "quad9-dot-2",
                         "cloudflare-doh", "cloudflare-doh-2", "cloudflare-udp", "quad9-udp"};
  for (size_t i = 0; i < n; i++) TEST_ASSERT_EQUAL_STRING(names[i], e[i].name);
  TEST_ASSERT_EQUAL_STRING("1.1.1.1", e[0].ip);
  TEST_ASSERT_EQUAL_STRING("cloudflare-dns.com", e[0].verifyName);
  TEST_ASSERT_EQUAL(853, e[0].port);
  TEST_ASSERT_EQUAL_STRING("dns.quad9.net", e[2].verifyName);
  TEST_ASSERT_EQUAL(static_cast<int>(upstream::TransportKind::kDoH), static_cast<int>(e[4].kind));
  TEST_ASSERT_EQUAL(443, e[4].port);
  TEST_ASSERT_EQUAL(static_cast<int>(upstream::TransportKind::kUdp), static_cast<int>(e[6].kind));
  TEST_ASSERT_EQUAL(53, e[6].port);
}

static void test_chain_respects_fallback_switches_and_custom_provider() {
  AppConfig c;
  c.plainFallback = false;
  c.dohFallback = false;
  config::Endpoint e[8];
  TEST_ASSERT_EQUAL(4, config::buildChain(c, e, 8));  // DoT only: strict privacy
  c = AppConfig{};
  c.primary = Provider::kCustom;
  c.secondary = Provider::kNone;
  strcpy(c.customIp, "94.140.14.14");
  strcpy(c.customName, "dns.adguard-dns.com");
  c.customDoh = true;
  const size_t n = config::buildChain(c, e, 8);
  TEST_ASSERT_EQUAL(3, n);  // one DoT (no second IP), one DoH, one plain
  TEST_ASSERT_EQUAL_STRING("custom-dot", e[0].name);
  TEST_ASSERT_EQUAL_STRING("dns.adguard-dns.com", e[0].verifyName);
  TEST_ASSERT_EQUAL_STRING("custom-doh", e[1].name);
  TEST_ASSERT_EQUAL_STRING("custom-udp", e[2].name);
  TEST_ASSERT_EQUAL(2, config::buildChain(c, e, 2));  // respects the output limit
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_defaults_match_the_design);
  RUN_TEST(test_field_validation);
  RUN_TEST(test_values_are_trimmed);
  RUN_TEST(test_cross_field_validation);
  RUN_TEST(test_round_trip_through_nvs);
  RUN_TEST(test_load_handles_empty_future_and_corrupt_stores);
  RUN_TEST(test_restart_needed_only_for_dns_settings);
  RUN_TEST(test_default_chain_order);
  RUN_TEST(test_chain_respects_fallback_switches_and_custom_provider);
  return UNITY_END();
}
