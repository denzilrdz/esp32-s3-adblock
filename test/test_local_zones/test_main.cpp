// Tests for lib/core/dns/local_zones: names answered without asking upstream.

#include <unity.h>

#include <cstring>

#include "dns/local_zones.h"

using dns::LocalAnswer;

void setUp() {}
void tearDown() {}

static LocalAnswer classify(const char* name, const dns::LocalZoneOptions& o = {}) {
  return dns::classifyLocal(name, strlen(name), o);
}

static void assertAnswer(LocalAnswer want, const char* name, const dns::LocalZoneOptions& o = {}) {
  TEST_ASSERT_EQUAL_MESSAGE(static_cast<int>(want), static_cast<int>(classify(name, o)), name);
}

static void test_localhost_and_subdomains() {
  assertAnswer(LocalAnswer::kLocalhost, "localhost");
  assertAnswer(LocalAnswer::kLocalhost, "app.localhost");
  assertAnswer(LocalAnswer::kNone, "notlocalhost");     // label boundary
  assertAnswer(LocalAnswer::kNone, "localhost.example"); // only as the suffix
}

static void test_firefox_canary_on_by_default() {
  assertAnswer(LocalAnswer::kNxDomain, "use-application-dns.net");
  assertAnswer(LocalAnswer::kNone, "x.use-application-dns.net");
  dns::LocalZoneOptions off;
  off.firefoxCanary = false;
  assertAnswer(LocalAnswer::kNone, "use-application-dns.net", off);
}

static void test_icloud_private_relay_off_by_default() {
  assertAnswer(LocalAnswer::kNone, "mask.icloud.com");
  dns::LocalZoneOptions on;
  on.icloudPrivateRelay = true;
  assertAnswer(LocalAnswer::kNxDomain, "mask.icloud.com", on);
  assertAnswer(LocalAnswer::kNxDomain, "mask-h2.icloud.com", on);
  assertAnswer(LocalAnswer::kNone, "www.icloud.com", on);
}

static void test_private_reverse_zones_and_mdns() {
  assertAnswer(LocalAnswer::kNxDomain, "1.1.168.192.in-addr.arpa");
  assertAnswer(LocalAnswer::kNxDomain, "4.3.2.10.in-addr.arpa");
  assertAnswer(LocalAnswer::kNxDomain, "9.9.20.172.in-addr.arpa");
  assertAnswer(LocalAnswer::kNone, "9.9.32.172.in-addr.arpa");   // 172.32/16 is public
  assertAnswer(LocalAnswer::kNone, "1.1.1.1.in-addr.arpa");      // public reverse goes upstream
  assertAnswer(LocalAnswer::kNone, "110.in-addr.arpa");          // "10" must be a whole label
  assertAnswer(LocalAnswer::kNxDomain, "printer.local");
  assertAnswer(LocalAnswer::kNxDomain, "1.0.0.0.d.f.ip6.arpa");
  dns::LocalZoneOptions off;
  off.privateReverse = false;
  assertAnswer(LocalAnswer::kNone, "1.1.168.192.in-addr.arpa", off);
}

static void test_ordinary_names_are_not_local() {
  assertAnswer(LocalAnswer::kNone, "example.com");
  assertAnswer(LocalAnswer::kNone, "");
  assertAnswer(LocalAnswer::kNone, "arpa");
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_localhost_and_subdomains);
  RUN_TEST(test_firefox_canary_on_by_default);
  RUN_TEST(test_icloud_private_relay_off_by_default);
  RUN_TEST(test_private_reverse_zones_and_mdns);
  RUN_TEST(test_ordinary_names_are_not_local);
  return UNITY_END();
}
