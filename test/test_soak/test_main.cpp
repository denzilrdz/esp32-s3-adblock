// Long-run soak test of the DNS pipeline the board runs (src/tasks/dns_service.cpp):
// client query -> parseQuery -> cache lookup -> Forwarder (pending slots recycled like
// the board's 32-entry pool) -> answer -> cache insert -> finalizeForClient.
//
// Hundreds of thousands of queries with a realistic but hostile upstream mix (big and
// multi-record answers, NXDOMAIN/NODATA/SERVFAIL, silence, dropped connections,
// malformed and mismatched replies) and simulated time, run under ASan + UBSan. It
// checks the invariants whose violation would corrupt memory on the board: every
// pending slot is completed exactly once, the in-flight table and cache stay within
// bounds, and every client reply is a well-formed DNS message.

#include <unity.h>

#include <cstring>
#include <string>
#include <vector>

#include "cache/response_cache.h"
#include "dns/message.h"
#include "fakes/dns_builder.h"
#include "fakes/fake_clock.h"
#include "fakes/fake_random.h"
#include "fakes/fake_transport.h"
#include "upstream/forwarder.h"

namespace {

class NullLogger final : public hal::ILogger {
 public:
  void vlog(hal::LogLevel, const char*, const char*, va_list) override {}
  bool enabled(hal::LogLevel) const override { return false; }
};

// Deterministic PRNG for the workload (separate from the forwarder's IRandom).
struct Rng {
  uint64_t s = 0x9E3779B97F4A7C15ull;
  uint32_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return static_cast<uint32_t>(s >> 11);
  }
  uint32_t below(uint32_t n) { return next() % n; }
  bool chance(uint32_t perMille) { return below(1000) < perMille; }
};

constexpr size_t kPool = 32;  // the board's pending-query pool (= Forwarder::kMaxInFlight)
constexpr size_t kReplyCap = 4096;

struct Soak : upstream::IForwarderSink {
  FakeClock clock;
  FakeRandom random;
  NullLogger log;
  Rng rng;

  // Pool slots exactly like the board: a token is a slot index, taken on a cache miss
  // and returned when the sink completes it.
  bool slotBusy[kPool] = {};
  dns::Query slotQuery[kPool];
  std::vector<uint32_t> freeSlots;

  cache::CacheConfig ccfg;
  std::vector<uint64_t> cacheMem;
  cache::ResponseCache* cache = nullptr;

  uint64_t queries = 0, hits = 0, answers = 0, failures = 0, poolFull = 0, badReplies = 0;
  uint64_t doubleCompletions = 0, unknownCompletions = 0;
  uint8_t reply[kReplyCap];

  void onAnswer(uint32_t token, const dns::Query& q, const uint8_t* answer, size_t len,
                const dns::ResponseInfo& info, bool authenticated) override {
    if (!take(token, q)) return;
    if (authenticated) cache->insert(q, answer, len, info);
    dns::ClientReplyOptions co;
    co.authenticatedUpstream = authenticated;
    co.sizeLimit = q.udpReplyLimit();
    size_t n = dns::finalizeForClient(answer, len, q, co, reply, kReplyCap);
    if (n == 0) n = dns::buildErrorReply(q, dns::Rcode::kServFail, reply, kReplyCap);
    checkReply(q, n);
    answers++;
  }
  void onFailure(uint32_t token, const dns::Query& q) override {
    if (!take(token, q)) return;
    checkReply(q, dns::buildErrorReply(q, dns::Rcode::kServFail, reply, kReplyCap));
    failures++;
  }

  bool take(uint32_t token, const dns::Query& q) {
    if (token >= kPool) {
      unknownCompletions++;
      return false;
    }
    if (!slotBusy[token]) {
      doubleCompletions++;  // on the board: the slot is queued twice -> two queries share it
      return false;
    }
    TEST_ASSERT_EQUAL_UINT16(slotQuery[token].qtype, q.qtype);
    TEST_ASSERT_EQUAL(slotQuery[token].qnameWireLen, q.qnameWireLen);
    slotBusy[token] = false;
    freeSlots.push_back(token);
    return true;
  }

  void checkReply(const dns::Query& q, size_t n) {
    TEST_ASSERT_TRUE(n >= dns::kHeaderSize && n <= kReplyCap);
    if (n > q.udpReplyLimit()) badReplies++;
    dns::ResponseInfo info;
    if (!dns::inspectResponse(reply, n, info)) badReplies++;
  }
};

std::string randomLabel(Rng& r, size_t len) {
  static const char kAlpha[] = "abcdefghijklmnopqrstuvwxyz0123456789-";
  std::string s;
  for (size_t i = 0; i < len; i++) s += kAlpha[r.below(i == 0 || i + 1 == len ? 36 : 37)];
  return s;
}

std::string randomName(Rng& r, uint32_t id) {
  // Mostly ordinary names; some long ones close to the 253-character limit.
  if (r.chance(20)) {
    std::string n;
    while (n.size() < 200) n += randomLabel(r, 1 + r.below(63)) + ".";
    return n + "example";
  }
  return randomLabel(r, 3 + r.below(12)) + std::to_string(id) + "." + randomLabel(r, 4 + r.below(8)) + ".com";
}

// Upstream behaviour: realistic answers plus the rare odd replies.
testdns::Bytes upstreamReply(Rng& r, const testdns::Bytes& query) {
  dns::Query q;
  if (dns::parseQuery(query.data(), query.size(), q) != dns::ParseStatus::kOk) return {};
  const uint16_t id = testdns::get16(query, 0);
  const uint32_t roll = r.below(1000);
  const uint32_t ttl = r.chance(50) ? 0 : (r.chance(100) ? r.below(86400 * 3) : 30 + r.below(3600));
  if (roll < 15) return {};  // dropped: hedge, then SERVFAIL at the deadline
  if (roll < 18) {           // garbage with the right ID
    testdns::Bytes g(2 + r.below(600));
    for (auto& b : g) b = static_cast<uint8_t>(r.next());
    g[0] = static_cast<uint8_t>(id >> 8);
    g[1] = static_cast<uint8_t>(id);
    if (g.size() > 2) g[2] |= 0x80;  // QR
    return g;
  }
  if (roll < 20)  // right ID, someone else's question (must be ignored)
    return testdns::ResponseBuilder(id, "other.example", q.qtype, 0x8180).answerA(300, 1, 2, 3, 4).build();
  if (roll < 50) return testdns::ResponseBuilder(id, q.qname, q.qtype, 0x8182).opt().build();  // SERVFAIL
  if (roll < 110)  // NXDOMAIN with SOA
    return testdns::ResponseBuilder(id, q.qname, q.qtype, 0x8183).authoritySoa(ttl, 900).opt().build();
  if (roll < 160)  // NODATA
    return testdns::ResponseBuilder(id, q.qname, q.qtype, 0x8180).authoritySoa(ttl, 300).opt().build();
  testdns::ResponseBuilder b(id, q.qname, q.qtype, r.chance(500) ? 0x81A0 : 0x8180);
  if (roll < 260) {
    b.answerTxt(ttl, 300 + r.below(3400));  // big: several cache blocks, truncated for 512-byte clients
  } else {
    const uint32_t records = 1 + r.below(r.chance(100) ? 40 : 6);
    for (uint32_t i = 0; i < records; i++)
      b.answerA(ttl + r.below(60), 10, static_cast<uint8_t>(i), static_cast<uint8_t>(r.next()), 1);
  }
  return r.chance(900) ? b.opt(1232, r.chance(300) ? r.below(400) : 0).build() : b.build();
}

void runSoak(uint64_t totalQueries, const cache::CacheConfig& ccfg, uint32_t uniquePerMille,
             uint32_t maxGapMs = 120) {
  Soak s;
  s.ccfg = ccfg;
  s.cacheMem.resize(cache::ResponseCache::requiredBytes(ccfg) / 8 + 1);
  cache::ResponseCache cache(ccfg, s.cacheMem.data(), s.clock);
  s.cache = &cache;
  for (uint32_t i = 0; i < kPool; i++) s.freeSlots.push_back(kPool - 1 - i);

  FakeTransport dot1("cloudflare-dot", upstream::TransportKind::kDoT, true, true);
  FakeTransport dot2("quad9-dot", upstream::TransportKind::kDoT, true, true);
  FakeTransport udp("cloudflare-udp", upstream::TransportKind::kUdp, false, true);
  Rng upRng;
  upRng.s = 0x1234567ull;
  for (FakeTransport* t : {&dot1, &dot2, &udp})
    t->responder = [&upRng](const testdns::Bytes& q) { return upstreamReply(upRng, q); };
  upstream::ITransport* chain[] = {&dot1, &dot2, &udp};
  upstream::ForwarderConfig fcfg;
  upstream::Forwarder fwd(fcfg, chain, 3, s.clock, s.random, s.log, s);

  std::vector<std::string> popular;
  for (uint32_t i = 0; i < 3000; i++) popular.push_back(randomName(s.rng, i));
  uint32_t uniqueId = 1000000;
  static const uint16_t kTypes[] = {dns::kTypeA,    dns::kTypeA,    dns::kTypeA,
                                    dns::kTypeAaaa, dns::kTypeAaaa, dns::kTypeHttps};

  for (uint64_t n = 0; n < totalQueries; n++) {
    // The upstream task polls between client queries; time moves on.
    s.clock.advanceMs(s.rng.below(maxGapMs));
    fwd.poll(0);
    // Occasional link trouble on the DoT connections.
    if (s.rng.chance(2)) dot1.mode = FakeTransport::Mode::kCloseAfterSend;
    if (s.rng.chance(1)) dot2.mode = FakeTransport::Mode::kRefuseConnect;
    if (s.rng.chance(20)) dot1.mode = dot2.mode = FakeTransport::Mode::kAnswer;
    if (s.rng.chance(1)) dot1.inbox.clear();  // replies lost with a reconnect

    const std::string name =
        s.rng.chance(uniquePerMille) ? randomName(s.rng, uniqueId++) : popular[s.rng.below(popular.size())];
    testdns::QueryOpts o;
    o.id = static_cast<uint16_t>(s.rng.next());
    o.edns = s.rng.chance(700);
    o.udpSize = s.rng.chance(200) ? 512 : (s.rng.chance(500) ? 1232 : 4096);
    o.dnssecOk = s.rng.chance(100);
    const testdns::Bytes pkt = testdns::makeQuery(name, kTypes[s.rng.below(6)], o);
    dns::Query q;
    if (dns::parseQuery(pkt.data(), pkt.size(), q) != dns::ParseStatus::kOk) continue;
    s.queries++;

    uint8_t scratch[kReplyCap];
    const size_t hit = cache.lookup(q, scratch, sizeof(scratch));
    if (hit) {
      dns::ClientReplyOptions co;
      co.authenticatedUpstream = true;
      co.sizeLimit = q.udpReplyLimit();
      const size_t len = dns::finalizeForClient(scratch, hit, q, co, s.reply, kReplyCap);
      TEST_ASSERT_TRUE(len > 0);
      s.checkReply(q, len);
      s.hits++;
      continue;
    }
    if (s.freeSlots.empty()) {
      s.poolFull++;  // board: SERVFAIL right away
      continue;
    }
    const uint32_t slot = s.freeSlots.back();
    s.freeSlots.pop_back();
    s.slotBusy[slot] = true;
    s.slotQuery[slot] = q;
    if (!fwd.submit(slot, q) && s.slotBusy[slot]) {  // table full: board answers SERVFAIL
      s.slotBusy[slot] = false;
      s.freeSlots.push_back(slot);
      s.poolFull++;
    }

    TEST_ASSERT_TRUE(fwd.inFlight() <= upstream::Forwarder::kMaxInFlight);
    if ((n & 0x3FF) == 0) {
      const cache::CacheStats cs = cache.stats();
      TEST_ASSERT_TRUE(cs.entries <= ccfg.maxEntries);
      TEST_ASSERT_TRUE(cs.freeBlocks <= ccfg.arenaBytes / cache::ResponseCache::kBlockSize);
      size_t busy = 0;
      for (bool b : s.slotBusy) busy += b;
      TEST_ASSERT_EQUAL(busy, fwd.inFlight());  // no slot lost or leaked
      TEST_ASSERT_EQUAL(kPool, busy + s.freeSlots.size());
    }
  }
  // Drain: every pending slot must still be completed (SERVFAIL by the deadline).
  for (int i = 0; i < 100; i++) {
    s.clock.advanceMs(100);
    fwd.poll(0);
  }
  TEST_ASSERT_EQUAL(0, fwd.inFlight());
  TEST_ASSERT_EQUAL(kPool, s.freeSlots.size());
  TEST_ASSERT_EQUAL_UINT64(0, s.doubleCompletions);
  TEST_ASSERT_EQUAL_UINT64(0, s.unknownCompletions);
  TEST_ASSERT_EQUAL_UINT64(0, s.badReplies);
  const cache::CacheStats cs = cache.stats();
  printf(
      "    %llu queries: %llu cache hits, %llu answered, %llu SERVFAIL, %llu pool full; cache %u entries, "
      "%llu evictions, %llu simulated hours\n",
      static_cast<unsigned long long>(s.queries), static_cast<unsigned long long>(s.hits),
      static_cast<unsigned long long>(s.answers), static_cast<unsigned long long>(s.failures),
      static_cast<unsigned long long>(s.poolFull), static_cast<unsigned>(cs.entries),
      static_cast<unsigned long long>(cs.evictions),
      static_cast<unsigned long long>(s.clock.monotonicMs() / 3600000));
  TEST_ASSERT_TRUE(s.answers > 0 && s.hits > 0);
}

}  // namespace

// Sizes keep the pre-commit run short (~10 s with sanitizers). For a long soak, build
// with -DSOAK_SCALE=10 (2026-10-23: 650k queries / 124 simulated hours, all clean).
#ifndef SOAK_SCALE
#define SOAK_SCALE 1
#endif

void setUp() {}
void tearDown() {}

// The board's real cache size, a day-plus of household traffic.
static void test_soak_board_cache_size() {
  runSoak(80000ull * SOAK_SCALE, cache::CacheConfig{}, 300);
}

// A tiny cache so eviction and block reuse run constantly.
static void test_soak_tiny_cache_constant_eviction() {
  cache::CacheConfig c;
  c.maxEntries = 300;
  c.arenaBytes = 48 * 1024;
  runSoak(50000ull * SOAK_SCALE, c, 600);
}

// Household pace (a query every ~3 s on average): days of simulated time, so cached
// answers mostly expire instead of being evicted.
static void test_soak_household_pace_for_days() {
  runSoak(40000ull * SOAK_SCALE, cache::CacheConfig{}, 300, 6000);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_soak_board_cache_size);
  RUN_TEST(test_soak_tiny_cache_constant_eviction);
  RUN_TEST(test_soak_household_pace_for_days);
  return UNITY_END();
}
