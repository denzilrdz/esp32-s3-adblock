// Tests for lib/core/cache: TTL aging and expiry, LRU eviction (by entry count and by
// payload memory), negative caching, what is never cached, and key separation.

#include <unity.h>

#include <memory>
#include <vector>

#include "cache/response_cache.h"
#include "fakes/dns_builder.h"
#include "fakes/fake_clock.h"

using namespace testdns;

static FakeClock fakeClock;
static std::vector<uint64_t> memory;  // uint64 storage keeps the region 8-byte aligned
static std::unique_ptr<cache::ResponseCache> c;
static uint8_t out[8192];

static void makeCache(const cache::CacheConfig& cfg) {
  memory.assign(cache::ResponseCache::requiredBytes(cfg) / 8 + 1, 0);
  c = std::make_unique<cache::ResponseCache>(cfg, memory.data(), fakeClock);
}

void setUp() {
  fakeClock = FakeClock{};
  cache::CacheConfig cfg;
  cfg.maxEntries = 8;
  cfg.arenaBytes = 64 * 1024;
  makeCache(cfg);
}
void tearDown() { c.reset(); }

static dns::Query query(const std::string& name, uint16_t type = dns::kTypeA, bool dnssecOk = false) {
  QueryOpts o;
  o.edns = dnssecOk;
  o.dnssecOk = dnssecOk;
  Bytes pkt = makeQuery(name, type, o);
  dns::Query q;
  dns::parseQuery(pkt.data(), pkt.size(), q);
  return q;
}

static bool put(const dns::Query& q, Bytes resp) {
  dns::ResponseInfo info;
  TEST_ASSERT_TRUE(dns::inspectResponse(resp.data(), resp.size(), info));
  return c->insert(q, resp.data(), resp.size(), info);
}

static Bytes answerA(const std::string& name, uint32_t ttl) {
  return ResponseBuilder(1, name, dns::kTypeA).answerA(ttl, 1, 2, 3, 4).build();
}

static uint32_t firstAnswerTtl(size_t qnameWireLen) {
  return get32(out, 12 + qnameWireLen + 4 + 6);
}

static void test_hit_returns_answer_with_aged_ttl() {
  dns::Query q = query("example.com");
  TEST_ASSERT_TRUE(put(q, answerA("example.com", 300)));
  size_t n = c->lookup(q, out, sizeof(out));
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL_UINT32(300, firstAnswerTtl(q.qnameWireLen));
  fakeClock.advanceSeconds(120);
  n = c->lookup(q, out, sizeof(out));
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL_UINT32(180, firstAnswerTtl(q.qnameWireLen));
  TEST_ASSERT_EQUAL(2, c->stats().hits);
}

static void test_entry_expires_exactly_at_ttl() {
  dns::Query q = query("example.com");
  put(q, answerA("example.com", 60));
  fakeClock.advanceMs(59999);
  TEST_ASSERT_TRUE(c->lookup(q, out, sizeof(out)) > 0);
  fakeClock.advanceMs(1);
  TEST_ASSERT_EQUAL(0, c->lookup(q, out, sizeof(out)));
  TEST_ASSERT_EQUAL(0, c->stats().entries);
}

static void test_ttl_is_clamped_to_configured_bounds() {
  cache::CacheConfig cfg;
  cfg.maxEntries = 4;
  cfg.arenaBytes = 4096;
  cfg.minTtl = 30;
  cfg.maxTtl = 3600;
  makeCache(cfg);
  dns::Query q = query("short.example");
  put(q, answerA("short.example", 5));
  fakeClock.advanceSeconds(20);
  TEST_ASSERT_TRUE(c->lookup(q, out, sizeof(out)) > 0);  // kept for minTtl, served TTL 0
  TEST_ASSERT_EQUAL_UINT32(0, firstAnswerTtl(q.qnameWireLen));
  dns::Query lq = query("long.example");
  put(lq, answerA("long.example", 999999));
  fakeClock.advanceSeconds(3600);
  TEST_ASSERT_EQUAL(0, c->lookup(lq, out, sizeof(out)));
}

static void test_lru_evicts_least_recently_used_entry() {
  cache::CacheConfig cfg;
  cfg.maxEntries = 2;
  cfg.arenaBytes = 4096;
  makeCache(cfg);
  dns::Query a = query("a.example"), b = query("b.example"), d = query("d.example");
  put(a, answerA("a.example", 300));
  put(b, answerA("b.example", 300));
  TEST_ASSERT_TRUE(c->lookup(a, out, sizeof(out)) > 0);  // a becomes most recent
  put(d, answerA("d.example", 300));                     // evicts b
  TEST_ASSERT_TRUE(c->lookup(a, out, sizeof(out)) > 0);
  TEST_ASSERT_EQUAL(0, c->lookup(b, out, sizeof(out)));
  TEST_ASSERT_TRUE(c->lookup(d, out, sizeof(out)) > 0);
  TEST_ASSERT_EQUAL(1, c->stats().evictions);
}

static void test_payload_memory_pressure_evicts_until_it_fits() {
  cache::CacheConfig cfg;
  cfg.maxEntries = 64;
  cfg.arenaBytes = 8 * cache::ResponseCache::kBlockSize;  // 1 KB of payload
  makeCache(cfg);
  dns::Query t1 = query("t1.example", dns::kTypeTxt), t2 = query("t2.example", dns::kTypeTxt);
  TEST_ASSERT_TRUE(put(t1, ResponseBuilder(1, "t1.example", dns::kTypeTxt).answerTxt(300, 500).build()));
  TEST_ASSERT_TRUE(put(t2, ResponseBuilder(1, "t2.example", dns::kTypeTxt).answerTxt(300, 500).build()));
  TEST_ASSERT_EQUAL(0, c->lookup(t1, out, sizeof(out)));  // t1 evicted to make room
  TEST_ASSERT_TRUE(c->lookup(t2, out, sizeof(out)) > 0);
  // An answer bigger than the whole arena is refused instead of flushing everything.
  dns::Query huge = query("huge.example", dns::kTypeTxt);
  TEST_ASSERT_FALSE(put(huge, ResponseBuilder(1, "huge.example", dns::kTypeTxt).answerTxt(300, 2000).build()));
  TEST_ASSERT_TRUE(c->lookup(t2, out, sizeof(out)) > 0);
}

static void test_payload_spanning_blocks_round_trips_exactly() {
  dns::Query q = query("multi.example", dns::kTypeTxt);
  Bytes resp = ResponseBuilder(1, "multi.example", dns::kTypeTxt).answerTxt(300, 700).build();
  put(q, resp);
  size_t n = c->lookup(q, out, sizeof(out));
  TEST_ASSERT_EQUAL(resp.size(), n);
  TEST_ASSERT_EQUAL_HEX8_ARRAY(resp.data(), out, n);
}

static void test_negative_answers_use_soa_and_caps() {
  dns::Query nx = query("nx.example");
  put(nx, ResponseBuilder(1, "nx.example", dns::kTypeA, 0x8183).authoritySoa(3600, 600).build());
  fakeClock.advanceSeconds(599);
  TEST_ASSERT_TRUE(c->lookup(nx, out, sizeof(out)) > 0);
  fakeClock.advanceSeconds(1);
  TEST_ASSERT_EQUAL(0, c->lookup(nx, out, sizeof(out)));

  dns::Query nodata = query("v4only.example", dns::kTypeAaaa);
  put(nodata, ResponseBuilder(1, "v4only.example", dns::kTypeAaaa).build());  // no SOA
  fakeClock.advanceSeconds(29);
  TEST_ASSERT_TRUE(c->lookup(nodata, out, sizeof(out)) > 0);
  fakeClock.advanceSeconds(1);
  TEST_ASSERT_EQUAL(0, c->lookup(nodata, out, sizeof(out)));

  dns::Query capped = query("capped.example");
  put(capped, ResponseBuilder(1, "capped.example", dns::kTypeA, 0x8183).authoritySoa(86400, 86400).build());
  fakeClock.advanceSeconds(10800);
  TEST_ASSERT_EQUAL(0, c->lookup(capped, out, sizeof(out)));
}

static void test_never_caches_servfail_truncated_or_zero_ttl() {
  dns::Query q = query("bad.example");
  TEST_ASSERT_FALSE(put(q, ResponseBuilder(1, "bad.example", dns::kTypeA, 0x8182).build()));
  TEST_ASSERT_FALSE(put(q, ResponseBuilder(1, "bad.example", dns::kTypeA, 0x8185).build()));
  TEST_ASSERT_FALSE(put(q, ResponseBuilder(1, "bad.example", dns::kTypeA, 0x8380).answerA(60, 1, 1, 1, 1).build()));
  TEST_ASSERT_FALSE(put(q, answerA("bad.example", 0)));
  TEST_ASSERT_EQUAL(0, c->stats().entries);
}

static void test_refuses_answers_still_carrying_opt() {
  dns::Query q = query("opt.example");
  Bytes r = ResponseBuilder(1, "opt.example", dns::kTypeA).answerA(60, 1, 1, 1, 1).opt().build();
  TEST_ASSERT_FALSE(put(q, r));
}

static void test_keys_separate_type_and_do_bit_but_ignore_case() {
  dns::Query a = query("Example.COM");
  put(a, answerA("example.com", 300));
  TEST_ASSERT_TRUE(c->lookup(query("example.com"), out, sizeof(out)) > 0);
  TEST_ASSERT_EQUAL(0, c->lookup(query("example.com", dns::kTypeAaaa), out, sizeof(out)));
  TEST_ASSERT_EQUAL(0, c->lookup(query("example.com", dns::kTypeA, true), out, sizeof(out)));
}

static void test_reinsert_replaces_existing_entry() {
  dns::Query q = query("example.com");
  put(q, answerA("example.com", 300));
  put(q, answerA("example.com", 50));
  TEST_ASSERT_EQUAL(1, c->stats().entries);
  c->lookup(q, out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT32(50, firstAnswerTtl(q.qnameWireLen));
}

static void test_clear_empties_and_restores_memory() {
  const uint32_t freeBefore = c->stats().freeBlocks;
  put(query("a.example"), answerA("a.example", 300));
  put(query("b.example"), answerA("b.example", 300));
  c->clear();
  TEST_ASSERT_EQUAL(0, c->stats().entries);
  TEST_ASSERT_EQUAL(freeBefore, c->stats().freeBlocks);
  TEST_ASSERT_EQUAL(0, c->lookup(query("a.example"), out, sizeof(out)));
}

static void test_many_inserts_keep_accounting_consistent() {
  for (int i = 0; i < 500; i++) {
    std::string name = "n" + std::to_string(i) + ".example";
    put(query(name), answerA(name, 300 + i));
    if (i % 7 == 0) fakeClock.advanceSeconds(1);
  }
  const auto st = c->stats();
  TEST_ASSERT_EQUAL(8, st.entries);
  TEST_ASSERT_EQUAL(492, st.evictions);
  TEST_ASSERT_TRUE(c->lookup(query("n499.example"), out, sizeof(out)) > 0);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_hit_returns_answer_with_aged_ttl);
  RUN_TEST(test_entry_expires_exactly_at_ttl);
  RUN_TEST(test_ttl_is_clamped_to_configured_bounds);
  RUN_TEST(test_lru_evicts_least_recently_used_entry);
  RUN_TEST(test_payload_memory_pressure_evicts_until_it_fits);
  RUN_TEST(test_payload_spanning_blocks_round_trips_exactly);
  RUN_TEST(test_negative_answers_use_soa_and_caps);
  RUN_TEST(test_never_caches_servfail_truncated_or_zero_ttl);
  RUN_TEST(test_refuses_answers_still_carrying_opt);
  RUN_TEST(test_keys_separate_type_and_do_bit_but_ignore_case);
  RUN_TEST(test_reinsert_replaces_existing_entry);
  RUN_TEST(test_clear_empties_and_restores_memory);
  RUN_TEST(test_many_inserts_keep_accounting_consistent);
  return UNITY_END();
}
