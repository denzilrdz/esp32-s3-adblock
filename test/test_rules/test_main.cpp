// Tests for lib/core/rules/rewrites (temporary DNS rewrites: validation, matching,
// aliases, expiry, persistence) and lib/core/dns/rewrite_reply (the replies).

#include <unity.h>

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "dns/message.h"
#include "dns/name.h"
#include "dns/rewrite_reply.h"
#include "fakes/dns_builder.h"
#include "rules/rewrites.h"

using dns::RewriteAnswer;
using rules::RewriteStatus;
using rules::RewriteTable;
using rules::TargetKind;
using testdns::Bytes;

void setUp() {}
void tearDown() {}

namespace {

constexpr uint64_t kNow = 1000000;  // monotonic ms
constexpr uint64_t kMin = 60000;

std::unique_ptr<RewriteTable> table() {
  return std::unique_ptr<RewriteTable>(new RewriteTable());
}

void expectStatus(RewriteStatus want, RewriteStatus got, const char* what) {
  TEST_ASSERT_EQUAL_STRING_MESSAGE(rules::rewriteStatusMessage(want), rules::rewriteStatusMessage(got), what);
}

bool resolve(const RewriteTable& t, const char* name, RewriteAnswer& rw, uint64_t now = kNow) {
  return t.resolve(name, strlen(name), now, rw);
}

std::string wireText(const uint8_t* w, size_t len) {
  std::string s;
  size_t i = 0;
  while (i < len && w[i]) {
    if (!s.empty()) s += '.';
    s.append(reinterpret_cast<const char*>(w + i + 1), w[i]);
    i += 1 + w[i];
  }
  return s;
}

std::string hop(const RewriteAnswer& rw, size_t i) {
  size_t len;
  const uint8_t* w = rw.hop(i, len);
  return wireText(w, len);
}

dns::Query query(const std::string& name, uint16_t type, const testdns::QueryOpts& o = {}) {
  const Bytes b = testdns::makeQuery(name, type, o);
  dns::Query q;
  TEST_ASSERT_EQUAL(static_cast<int>(dns::ParseStatus::kOk),
                    static_cast<int>(dns::parseQuery(b.data(), b.size(), q)));
  return q;
}

// A decoded reply, for assertions.
struct Rec {
  std::string name;
  uint16_t type;
  uint32_t ttl;
  std::string data;  // dotted name for CNAME/NS/PTR, a.b.c.d for A, hex groups for AAAA, raw otherwise
  Bytes raw;
};
struct Reply {
  uint16_t id, flags, qd, an, ns, ar;
  std::string qname;
  uint16_t qtype;
  std::vector<Rec> answers, authority, additional;
  uint16_t rcode() const { return flags & 0xF; }
};

Reply decode(const uint8_t* m, size_t n) {
  Reply r{};
  TEST_ASSERT_TRUE(n >= 12);
  r.id = testdns::get16(m, 0);
  r.flags = testdns::get16(m, 2);
  r.qd = testdns::get16(m, 4);
  r.an = testdns::get16(m, 6);
  r.ns = testdns::get16(m, 8);
  r.ar = testdns::get16(m, 10);
  uint8_t w[dns::kMaxNameWire];
  size_t wl;
  size_t at = 12;
  if (r.qd) {
    at = dns::readName(m, n, 12, w, wl);
    TEST_ASSERT_TRUE(at > 0 && at + 4 <= n);
    r.qname = wireText(w, wl);
    r.qtype = testdns::get16(m, at);
    at += 4;
  }
  for (int sec = 0; sec < 3; sec++) {
    const uint16_t count = sec == 0 ? r.an : sec == 1 ? r.ns : r.ar;
    for (uint16_t k = 0; k < count; k++) {
      Rec rec;
      at = dns::readName(m, n, at, w, wl);
      TEST_ASSERT_TRUE_MESSAGE(at > 0 && at + 10 <= n, "record header");
      rec.name = wireText(w, wl);
      rec.type = testdns::get16(m, at);
      rec.ttl = testdns::get32(m, at + 4);
      const size_t rdlen = testdns::get16(m, at + 8);
      const size_t rd = at + 10;
      TEST_ASSERT_TRUE_MESSAGE(rd + rdlen <= n, "rdata overruns");
      rec.raw.assign(m + rd, m + rd + rdlen);
      if (rec.type == dns::kTypeCname || rec.type == dns::kTypeNs || rec.type == dns::kTypePtr) {
        const size_t e = dns::readName(m, n, rd, w, wl);
        TEST_ASSERT_EQUAL_MESSAGE(rd + rdlen, e, "name rdata length");
        rec.data = wireText(w, wl);
      } else if (rec.type == dns::kTypeA && rdlen == 4) {
        rec.data = std::to_string(m[rd]) + "." + std::to_string(m[rd + 1]) + "." + std::to_string(m[rd + 2]) +
                   "." + std::to_string(m[rd + 3]);
      } else if (rec.type == dns::kTypeAaaa && rdlen == 16) {
        char buf[48];
        rules::formatIpv6(m + rd, buf, sizeof(buf));
        rec.data = buf;
      }
      at = rd + rdlen;
      (sec == 0 ? r.answers : sec == 1 ? r.authority : r.additional).push_back(rec);
    }
  }
  TEST_ASSERT_EQUAL_MESSAGE(n, at, "trailing bytes");
  return r;
}

Reply reply(const dns::Query& q, const RewriteAnswer& rw, const Bytes* target = nullptr,
            size_t limit = 1232) {
  uint8_t out[4096];
  const size_t n = dns::buildRewriteReply(q, rw, target ? target->data() : nullptr,
                                          target ? target->size() : 0, limit, out, sizeof(out));
  TEST_ASSERT_TRUE(n > 0);
  return decode(out, n);
}

}  // namespace

// ---------------------------------------------------------------------------
// Input validation

static void test_domain_validation() {
  char d[300];
  uint8_t len;
  bool wc;
  struct Case {
    const char* in;
    RewriteStatus want;
    const char* norm;
    bool wildcard;
  };
  const Case cases[] = {
      {"nas", RewriteStatus::kAdded, "nas", false},  // single-label LAN names are fine
      {"  App.Example.COM.  ", RewriteStatus::kAdded, "app.example.com", false},
      {"*.example.com", RewriteStatus::kAdded, "example.com", true},
      {"*.Example.com.", RewriteStatus::kAdded, "example.com", true},
      {"_dmarc.example.com", RewriteStatus::kAdded, "_dmarc.example.com", false},
      {"*.com", RewriteStatus::kBadDomain, "", false},  // a whole TLD
      {"*", RewriteStatus::kBadDomain, "", false},
      {"*.", RewriteStatus::kBadDomain, "", false},
      {"a.*.example.com", RewriteStatus::kBadDomain, "", false},
      {"**.example.com", RewriteStatus::kBadDomain, "", false},
      {"", RewriteStatus::kBadDomain, "", false},
      {"   ", RewriteStatus::kBadDomain, "", false},
      {".", RewriteStatus::kBadDomain, "", false},
      {"a..b", RewriteStatus::kBadDomain, "", false},
      {".example.com", RewriteStatus::kBadDomain, "", false},
      {"example.com..", RewriteStatus::kBadDomain, "", false},
      {"exa mple.com", RewriteStatus::kBadDomain, "", false},
      {"exämple.com", RewriteStatus::kBadDomain, "", false},
      {"1.2.3.4", RewriteStatus::kBadDomain, "", false},  // numeric TLD: an IP typed in the wrong box
      {"10.0.0.1.example.com", RewriteStatus::kAdded, "10.0.0.1.example.com", false},
      {"localhost", RewriteStatus::kLocalName, "", false},
      {"app.localhost", RewriteStatus::kLocalName, "", false},
      {"*.localhost", RewriteStatus::kBadDomain, "", false},  // one label after "*."
      {"-nas.home", RewriteStatus::kBadDomain, "", false},
      {"nas-.home", RewriteStatus::kBadDomain, "", false},
      {"my-nas.home", RewriteStatus::kAdded, "my-nas.home", false},
      {"printer.local", RewriteStatus::kLocalName, "", false},
      {"*.local", RewriteStatus::kBadDomain, "", false},  // one label after "*."
      {"*.home.local", RewriteStatus::kLocalName, "", false},
      {"1.168.192.in-addr.arpa", RewriteStatus::kLocalName, "", false},
      {"use-application-dns.net", RewriteStatus::kLocalName, "", false},
      {"mask.icloud.com", RewriteStatus::kLocalName, "", false},
      {"*.in-addr.arpa", RewriteStatus::kAdded, "in-addr.arpa", true},
  };
  for (const Case& c : cases) {
    const RewriteStatus st = rules::parseRewriteDomain(c.in, d, len, wc);
    expectStatus(c.want, st, c.in);
    if (st == RewriteStatus::kAdded) {
      TEST_ASSERT_EQUAL_STRING_MESSAGE(c.norm, d, c.in);
      TEST_ASSERT_EQUAL_MESSAGE(strlen(c.norm), len, c.in);
      TEST_ASSERT_EQUAL_MESSAGE(c.wildcard, wc, c.in);
    }
  }
  // Length limits: 63-char labels, 253-char names.
  std::string l63(63, 'a'), l64(64, 'a');
  expectStatus(RewriteStatus::kAdded, rules::parseRewriteDomain((l63 + ".com").c_str(), d, len, wc), "63");
  expectStatus(RewriteStatus::kBadDomain, rules::parseRewriteDomain((l64 + ".com").c_str(), d, len, wc),
               "64");
  std::string n253 = l63 + "." + l63 + "." + l63 + "." + std::string(61, 'b');
  TEST_ASSERT_EQUAL(253, n253.size());
  expectStatus(RewriteStatus::kAdded, rules::parseRewriteDomain(n253.c_str(), d, len, wc), "253");
  expectStatus(RewriteStatus::kAdded, rules::parseRewriteDomain((n253 + ".").c_str(), d, len, wc), "253.");
  expectStatus(RewriteStatus::kBadDomain, rules::parseRewriteDomain((n253 + "b").c_str(), d, len, wc), "254");
  expectStatus(RewriteStatus::kAdded, rules::parseRewriteDomain(("*." + n253).c_str(), d, len, wc), "*.253");
  expectStatus(RewriteStatus::kBadDomain,
               rules::parseRewriteDomain(std::string(400, 'a').c_str(), d, len, wc), "400");
  expectStatus(RewriteStatus::kBadDomain, rules::parseRewriteDomain(nullptr, d, len, wc), "null");
}

static void test_ipv4_parsing() {
  uint8_t a[4];
  TEST_ASSERT_TRUE(rules::parseIpv4Strict("192.168.1.20", 12, a));
  TEST_ASSERT_EQUAL_UINT8(192, a[0]);
  TEST_ASSERT_EQUAL_UINT8(20, a[3]);
  TEST_ASSERT_TRUE(rules::parseIpv4Strict("0.0.0.0", 7, a));
  TEST_ASSERT_TRUE(rules::parseIpv4Strict("255.255.255.255", 15, a));
  for (const char* bad : {"256.1.1.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.04", "1..2.3", "1.2.3.",
                          ".1.2.3", "a.b.c.d", "1.2.3.4 ", "1234.1.1.1", ""})
    TEST_ASSERT_FALSE_MESSAGE(rules::parseIpv4Strict(bad, strlen(bad), a), bad);
}

static void test_ipv6_parsing_and_canonical_text() {
  struct Case {
    const char* in;
    const char* canon;
  };
  const Case ok[] = {
      {"::", "::"},
      {"::1", "::1"},
      {"1::", "1::"},
      {"2001:db8::1", "2001:db8::1"},
      {"2001:DB8:0:0:0:0:0:1", "2001:db8::1"},
      {"2001:0db8:0000:0000:0001:0000:0000:0001", "2001:db8::1:0:0:1"},  // first longest run
      {"2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},                  // a single 0 is not "::"
      {"fe80::1:2", "fe80::1:2"},
      {"::ffff:192.0.2.1", "::ffff:c000:201"},
      {"64:ff9b::192.0.2.33", "64:ff9b::c000:221"},
      {"1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"},
      {"1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304"},
      {"0:0:1:0:0:0:1:0", "0:0:1::1:0"},
  };
  for (const Case& c : ok) {
    uint8_t a[16];
    TEST_ASSERT_TRUE_MESSAGE(rules::parseIpv6(c.in, strlen(c.in), a), c.in);
    char buf[48];
    rules::formatIpv6(a, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(c.canon, buf, c.in);
  }
  for (const char* bad : {":", ":::", "1:::2", "1::2::3", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7",
                          "12345::", "g::1", "1:", ":1", "1::2:", "fe80::1%eth0", "[::1]", "::1.2.3",
                          "1.2.3.4::", "1:2:3:4:5:6:7:1.2.3.4", "::ffff:1.2.3.04", "1::2:3:4:5:6:7:8", ""}) {
    uint8_t a[16];
    TEST_ASSERT_FALSE_MESSAGE(rules::parseIpv6(bad, strlen(bad), a), bad);
  }
}

static void test_target_validation() {
  TargetKind k;
  uint8_t a[16];
  char t[300];
  uint8_t tl;
  expectStatus(RewriteStatus::kAdded, rules::parseRewriteTarget(" 10.0.0.5 ", k, a, t, tl), "v4");
  TEST_ASSERT_EQUAL(static_cast<int>(TargetKind::kIpv4), static_cast<int>(k));
  TEST_ASSERT_EQUAL_STRING("10.0.0.5", t);
  expectStatus(RewriteStatus::kAdded, rules::parseRewriteTarget("FE80::0001", k, a, t, tl), "v6");
  TEST_ASSERT_EQUAL(static_cast<int>(TargetKind::kIpv6), static_cast<int>(k));
  TEST_ASSERT_EQUAL_STRING("fe80::1", t);
  expectStatus(RewriteStatus::kAdded, rules::parseRewriteTarget("Other.Example.com.", k, a, t, tl), "name");
  TEST_ASSERT_EQUAL(static_cast<int>(TargetKind::kName), static_cast<int>(k));
  TEST_ASSERT_EQUAL_STRING("other.example.com", t);
  TEST_ASSERT_EQUAL(17, tl);
  for (const char* bad : {"", " ", "1.2.3", "300.1.1.1", "1.2.3.4.5", "::g", "*.example.com", "a..b", "-",
                          "http://example.com", "example.com/x", "exa mple.com"})
    expectStatus(RewriteStatus::kBadTarget, rules::parseRewriteTarget(bad, k, a, t, tl), bad);
  expectStatus(RewriteStatus::kLocalName, rules::parseRewriteTarget("localhost", k, a, t, tl), "localhost");
  expectStatus(RewriteStatus::kLocalName, rules::parseRewriteTarget("nas.local", k, a, t, tl), ".local");
}

// ---------------------------------------------------------------------------
// Table: add / update / conflict / remove / limits

static void test_add_update_conflict_remove() {
  auto t = table();
  expectStatus(RewriteStatus::kAdded, t->add("nas.home", "192.168.1.20", 60, kNow), "v4");
  expectStatus(RewriteStatus::kAdded, t->add("nas.home", "fd00::20", 60, kNow), "v6 beside v4");
  expectStatus(RewriteStatus::kUpdated, t->add("NAS.home.", "192.168.1.21", 30, kNow), "same kind replaces");
  TEST_ASSERT_EQUAL(2, t->size());
  expectStatus(RewriteStatus::kConflict, t->add("nas.home", "other.home", 60, kNow),
               "alias beside addresses");
  expectStatus(RewriteStatus::kAdded, t->add("tv.home", "nas.home", 60, kNow), "alias");
  expectStatus(RewriteStatus::kConflict, t->add("tv.home", "10.0.0.1", 60, kNow), "address beside alias");
  expectStatus(RewriteStatus::kConflict, t->add("tv.home", "::1", 60, kNow), "v6 beside alias");
  expectStatus(RewriteStatus::kUpdated, t->add("tv.home", "nas2.home", 60, kNow), "alias replaces alias");
  // An exact name and a wildcard on the same base are separate entries.
  expectStatus(RewriteStatus::kAdded, t->add("*.nas.home", "10.9.9.9", 60, kNow), "wildcard");

  rules::RewriteView v[RewriteTable::kMax];
  TEST_ASSERT_EQUAL(4, t->list(v, RewriteTable::kMax, kNow));
  TEST_ASSERT_EQUAL_STRING("nas.home", v[0].domain);
  TEST_ASSERT_EQUAL_STRING("192.168.1.21", v[0].target);
  TEST_ASSERT_EQUAL(30 * 60, v[0].secondsLeft);
  TEST_ASSERT_EQUAL_STRING("tv.home", v[2].domain);
  TEST_ASSERT_EQUAL_STRING("nas2.home", v[2].target);
  TEST_ASSERT_EQUAL_STRING("*.nas.home", v[3].domain);

  expectStatus(RewriteStatus::kNotFound, t->remove("nas.home", "192.168.1.20"), "old answer");
  expectStatus(RewriteStatus::kNotFound, t->remove("nas.home", "garbage"), "bad target");
  expectStatus(RewriteStatus::kNotFound, t->remove("", "1.2.3.4"), "bad domain");
  expectStatus(RewriteStatus::kRemoved, t->remove(" NAS.HOME ", "192.168.1.21"), "remove v4");
  expectStatus(RewriteStatus::kRemoved, t->remove("nas.home", "FD00:0::20"), "remove v6 (any spelling)");
  expectStatus(RewriteStatus::kNotFound, t->remove("nas.home", "fd00::20"), "already gone");
  expectStatus(RewriteStatus::kRemoved, t->remove("*.nas.home", "10.9.9.9"), "remove wildcard");
  TEST_ASSERT_EQUAL(1, t->size());
}

static void test_duration_limits() {
  auto t = table();
  expectStatus(RewriteStatus::kBadDuration, t->add("a.home", "1.2.3.4", 0, kNow), "0");
  expectStatus(RewriteStatus::kBadDuration, t->add("a.home", "1.2.3.4", 1441, kNow), "1441");
  expectStatus(RewriteStatus::kBadDuration, t->add("a.home", "1.2.3.4", 0xFFFFFFFFu, kNow), "huge");
  expectStatus(RewriteStatus::kAdded, t->add("a.home", "1.2.3.4", 1, kNow), "1");
  expectStatus(RewriteStatus::kAdded, t->add("b.home", "1.2.3.4", 1440, kNow), "1440");
  TEST_ASSERT_EQUAL(2, t->size());
  expectStatus(RewriteStatus::kSelfTarget, t->add("a.home", "A.Home.", 10, kNow), "self alias");
}

static void test_table_full_and_expired_slots_reused() {
  auto t = table();
  for (size_t i = 0; i < RewriteTable::kMax; i++) {
    const std::string d = "h" + std::to_string(i) + ".home";
    expectStatus(RewriteStatus::kAdded, t->add(d.c_str(), "10.0.0.1", i == 0 ? 1 : 60, kNow), d.c_str());
  }
  expectStatus(RewriteStatus::kFull, t->add("x.home", "10.0.0.1", 60, kNow), "full");
  expectStatus(RewriteStatus::kUpdated, t->add("h5.home", "10.0.0.2", 60, kNow), "update when full");
  // The 1-minute entry expires: its slot is free for the next add.
  expectStatus(RewriteStatus::kAdded, t->add("x.home", "10.0.0.1", 60, kNow + kMin), "slot freed");
  TEST_ASSERT_EQUAL(RewriteTable::kMax, t->size());
}

// ---------------------------------------------------------------------------
// Matching and expiry

static void test_exact_beats_wildcard_and_longest_wildcard_wins() {
  auto t = table();
  t->add("*.example.com", "10.0.0.1", 60, kNow);
  t->add("*.a.example.com", "10.0.0.2", 60, kNow);
  t->add("b.a.example.com", "10.0.0.3", 60, kNow);
  t->add("v6only.example.com", "fd00::6", 60, kNow);
  RewriteAnswer rw;
  TEST_ASSERT_FALSE(resolve(*t, "example.com", rw));   // a wildcard never covers its base
  TEST_ASSERT_FALSE(resolve(*t, "xexample.com", rw));  // label boundary
  TEST_ASSERT_FALSE(resolve(*t, "example.org", rw));
  TEST_ASSERT_FALSE(resolve(*t, "com", rw));
  TEST_ASSERT_TRUE(resolve(*t, "www.example.com", rw));
  TEST_ASSERT_EQUAL_UINT8(1, rw.v4[3]);
  TEST_ASSERT_TRUE(resolve(*t, "deep.www.example.com", rw));
  TEST_ASSERT_EQUAL_UINT8(1, rw.v4[3]);
  TEST_ASSERT_TRUE(resolve(*t, "x.a.example.com", rw));
  TEST_ASSERT_EQUAL_UINT8(2, rw.v4[3]);
  TEST_ASSERT_TRUE(resolve(*t, "b.a.example.com", rw));
  TEST_ASSERT_EQUAL_UINT8(3, rw.v4[3]);
  TEST_ASSERT_TRUE(resolve(*t, "c.b.a.example.com", rw));  // no wildcard on b.a: *.a wins
  TEST_ASSERT_EQUAL_UINT8(2, rw.v4[3]);
  // An exact entry hides the wildcard entirely, even for a type it has no address for.
  TEST_ASSERT_TRUE(resolve(*t, "v6only.example.com", rw));
  TEST_ASSERT_FALSE(rw.hasV4);
  TEST_ASSERT_TRUE(rw.hasV6);
  TEST_ASSERT_EQUAL(static_cast<int>(RewriteAnswer::End::kAddress), static_cast<int>(rw.end));
  TEST_ASSERT_EQUAL(0, rw.hops);
}

static void test_expiry_boundaries_and_ttl() {
  auto t = table();
  t->add("a.home", "10.0.0.1", 2, kNow);
  RewriteAnswer rw;
  TEST_ASSERT_TRUE(resolve(*t, "a.home", rw));
  TEST_ASSERT_EQUAL_UINT32(dns::kRewriteMaxTtl, rw.ttl);
  TEST_ASSERT_TRUE(resolve(*t, "a.home", rw, kNow + 2 * kMin - 10500));
  TEST_ASSERT_EQUAL_UINT32(11, rw.ttl);  // rounded up, below the cap
  TEST_ASSERT_TRUE(resolve(*t, "a.home", rw, kNow + 2 * kMin - 1));
  TEST_ASSERT_EQUAL_UINT32(1, rw.ttl);                            // never 0 while active
  TEST_ASSERT_FALSE(resolve(*t, "a.home", rw, kNow + 2 * kMin));  // expired exactly at the end
  rules::RewriteView v[4];
  TEST_ASSERT_EQUAL(0, t->list(v, 4, kNow + 2 * kMin));
  TEST_ASSERT_EQUAL(1, t->size());
  TEST_ASSERT_EQUAL(1, t->purgeExpired(kNow + 2 * kMin));
  TEST_ASSERT_EQUAL(0, t->size());
}

static void test_alias_chains() {
  auto t = table();
  t->add("app.test", "web.home", 60, kNow);
  t->add("web.home", "server.home", 10, kNow);
  t->add("server.home", "192.168.1.9", 60, kNow);
  t->add("server.home", "fd00::9", 60, kNow);
  t->add("yt.home", "restrict.youtube.com", 60, kNow);
  RewriteAnswer rw;
  TEST_ASSERT_TRUE(resolve(*t, "app.test", rw));
  TEST_ASSERT_EQUAL(static_cast<int>(RewriteAnswer::End::kAddress), static_cast<int>(rw.end));
  TEST_ASSERT_EQUAL(2, rw.hops);
  TEST_ASSERT_EQUAL_STRING("web.home", hop(rw, 0).c_str());
  TEST_ASSERT_EQUAL_STRING("server.home", hop(rw, 1).c_str());
  TEST_ASSERT_TRUE(rw.hasV4 && rw.hasV6);
  TEST_ASSERT_EQUAL_UINT8(9, rw.v4[3]);
  TEST_ASSERT_EQUAL_UINT32(30, rw.ttl);
  TEST_ASSERT_TRUE(resolve(*t, "app.test", rw, kNow + 10 * kMin - 5000));
  TEST_ASSERT_EQUAL_UINT32(5, rw.ttl);  // the shortest-lived link sets the TTL
  // When the middle link expires, the chain stops at its first hop and goes upstream.
  TEST_ASSERT_TRUE(resolve(*t, "app.test", rw, kNow + 10 * kMin));
  TEST_ASSERT_EQUAL(static_cast<int>(RewriteAnswer::End::kForward), static_cast<int>(rw.end));
  TEST_ASSERT_EQUAL(1, rw.hops);
  // An alias to a name without a rewrite of its own resolves it upstream.
  TEST_ASSERT_TRUE(resolve(*t, "yt.home", rw));
  TEST_ASSERT_EQUAL(static_cast<int>(RewriteAnswer::End::kForward), static_cast<int>(rw.end));
  TEST_ASSERT_EQUAL_STRING("restrict.youtube.com", hop(rw, 0).c_str());
}

static void test_loops_are_refused_and_table_unchanged() {
  auto t = table();
  expectStatus(RewriteStatus::kAdded, t->add("a.home", "b.home", 60, kNow), "a->b");
  expectStatus(RewriteStatus::kLoop, t->add("b.home", "a.home", 60, kNow), "b->a");
  TEST_ASSERT_EQUAL(1, t->size());
  expectStatus(RewriteStatus::kAdded, t->add("b.home", "c.home", 60, kNow), "b->c");
  // Replacing c's rewrite with one that closes the loop keeps the old one.
  expectStatus(RewriteStatus::kAdded, t->add("c.home", "d.home", 60, kNow), "c->d");
  expectStatus(RewriteStatus::kLoop, t->add("c.home", "a.home", 60, kNow), "c->a");
  rules::RewriteView v[8];
  TEST_ASSERT_EQUAL(3, t->list(v, 8, kNow));
  TEST_ASSERT_EQUAL_STRING("d.home", v[2].target);
  // A wildcard whose target sits under it would point at itself forever.
  expectStatus(RewriteStatus::kLoop, t->add("*.lan.home", "x.lan.home", 60, kNow), "wildcard into itself");
  expectStatus(RewriteStatus::kAdded, t->add("*.lan.home", "lan.home", 60, kNow), "wildcard to its base");
  RewriteAnswer rw;
  TEST_ASSERT_TRUE(resolve(*t, "pc.lan.home", rw));
  TEST_ASSERT_EQUAL(static_cast<int>(RewriteAnswer::End::kForward), static_cast<int>(rw.end));
}

static void test_chain_longer_than_limit_is_refused() {
  auto t = table();
  // n0 -> n1 -> ... : the 8th alias is the last one allowed in a chain.
  for (size_t i = 0; i < dns::kMaxRewriteHops; i++) {
    const std::string d = "n" + std::to_string(i) + ".home", target = "n" + std::to_string(i + 1) + ".home";
    expectStatus(RewriteStatus::kAdded, t->add(d.c_str(), target.c_str(), 60, kNow), d.c_str());
  }
  RewriteAnswer rw;
  TEST_ASSERT_TRUE(resolve(*t, "n0.home", rw));
  TEST_ASSERT_EQUAL(dns::kMaxRewriteHops, rw.hops);
  TEST_ASSERT_EQUAL(static_cast<int>(RewriteAnswer::End::kForward), static_cast<int>(rw.end));
  expectStatus(RewriteStatus::kLoop, t->add("pre.home", "n0.home", 60, kNow), "9th alias in front");
  expectStatus(RewriteStatus::kLoop, t->add("n8.home", "n9.home", 60, kNow), "9th alias at the end");
  TEST_ASSERT_EQUAL(dns::kMaxRewriteHops, t->size());
  // Long names fill the chain's byte budget before the hop limit.
  auto t2 = table();
  const std::string big = std::string(60, 'x') + "." + std::string(60, 'y') + "." + std::string(60, 'z');
  // Each hop is 186 wire bytes: two fit the 512-byte chain, a third doesn't.
  for (int i = 0; i < 2; i++) {
    const std::string d = std::to_string(i) + big, target = std::to_string(i + 1) + big;
    expectStatus(RewriteStatus::kAdded, t2->add(d.c_str(), target.c_str(), 60, kNow), "big");
  }
  expectStatus(RewriteStatus::kLoop, t2->add(("2" + big).c_str(), ("3" + big).c_str(), 60, kNow), "bytes");
  TEST_ASSERT_EQUAL(2, t2->size());
}

// ---------------------------------------------------------------------------
// Persistence

static std::string save(const RewriteTable& t, uint64_t now, bool synced, int64_t unixNow,
                        bool* ok = nullptr) {
  std::vector<char> buf(RewriteTable::kMaxTextBytes);
  size_t n = 0;
  const bool r = t.serialize(buf.data(), buf.size(), n, now, synced, unixNow);
  if (ok) *ok = r;
  return std::string(buf.data(), n);
}

static void test_serialize_parse_round_trip_and_activation() {
  auto t = table();
  t->add("nas.home", "192.168.1.20", 60, kNow);
  t->add("nas.home", "fd00::20", 90, kNow);
  t->add("*.dev.home", "nas.home", 1440, kNow);
  t->add("gone.home", "10.0.0.1", 1, kNow);
  const int64_t unixNow = 1800000000;
  const uint64_t later = kNow + kMin;  // gone.home has just expired
  const std::string text = save(*t, later, true, unixNow);
  TEST_ASSERT_EQUAL_STRING(
      "nas.home 192.168.1.20 1800003540\n"
      "nas.home fd00::20 1800005340\n"
      "*.dev.home nas.home 1800086340\n",
      text.c_str());

  // After a reboot: loaded entries wait for the clock and never answer before it.
  auto r = table();
  TEST_ASSERT_EQUAL(3, r->parse(text.data(), text.size()));
  TEST_ASSERT_TRUE(r->hasPending());
  RewriteAnswer rw;
  TEST_ASSERT_FALSE(resolve(*r, "nas.home", rw, 5000));
  rules::RewriteView v[4];
  TEST_ASSERT_EQUAL(3, r->list(v, 4, 5000));
  TEST_ASSERT_TRUE(v[0].pending);
  TEST_ASSERT_EQUAL(0, v[0].secondsLeft);
  // Saving with only pending entries works without a clock (keeps their times).
  bool ok = false;
  TEST_ASSERT_EQUAL_STRING(text.c_str(), save(*r, 5000, false, 0, &ok).c_str());
  TEST_ASSERT_TRUE(ok);

  // The clock syncs 30 minutes after the save: each entry gets its remaining time.
  TEST_ASSERT_EQUAL(0, r->activate(5000, unixNow + 1800));
  TEST_ASSERT_FALSE(r->hasPending());
  TEST_ASSERT_EQUAL(3, r->list(v, 4, 5000));
  TEST_ASSERT_EQUAL(3540 - 1800, v[0].secondsLeft);
  TEST_ASSERT_TRUE(resolve(*r, "x.dev.home", rw, 5000));
  TEST_ASSERT_EQUAL(1, rw.hops);
  TEST_ASSERT_TRUE(rw.hasV4 && rw.hasV6);
}

static void test_activation_drops_expired_and_future_entries() {
  const int64_t now = 1800000000;
  const std::string text = "a.home 10.0.0.1 " + std::to_string(now) + "\n" +          // ends right now
                           "b.home 10.0.0.2 " + std::to_string(now - 5) + "\n" +      // ended
                           "c.home 10.0.0.3 " + std::to_string(now + 1) + "\n" +      // 1 s left
                           "d.home 10.0.0.4 " + std::to_string(now + 86460) + "\n" +  // 24 h + 60 s: ok
                           "e.home 10.0.0.5 " + std::to_string(now + 86461) + "\n";   // clock went back
  auto t = table();
  TEST_ASSERT_EQUAL(5, t->parse(text.data(), text.size()));
  TEST_ASSERT_EQUAL(3, t->activate(kNow, now));
  rules::RewriteView v[8];
  TEST_ASSERT_EQUAL(2, t->list(v, 8, kNow));
  TEST_ASSERT_EQUAL_STRING("c.home", v[0].domain);
  TEST_ASSERT_EQUAL(1, v[0].secondsLeft);
  TEST_ASSERT_EQUAL_STRING("d.home", v[1].domain);
}

static void test_parse_skips_bad_lines() {
  const std::string text =
      "good.home 10.0.0.1 1800000100\r\n"
      "\n"
      "   \n"
      "missing.expiry 10.0.0.1\n"
      "bad.expiry 10.0.0.1 12x\n"
      "neg.expiry 10.0.0.1 -5\n"
      "zero.expiry 10.0.0.1 0\n"
      "extra.field 10.0.0.1 1800000100 more\n"
      "bad..domain 10.0.0.1 1800000100\n"
      "localhost 10.0.0.1 1800000100\n"
      "badtarget.home 300.0.0.1 1800000100\n"
      "self.home self.home 1800000100\n"
      "good.home 10.0.0.9 1800000100\n"    // duplicate: first line wins
      "good.home alias.home 1800000100\n"  // conflicts with the address
      "  spaced.home\t\tfd00::1   1800000100  \n" +
      std::string(400, 'x') +
      " 10.0.0.1 1800000100\n"
      "last.home 10.0.0.2 1800000100";  // no newline at the end
  auto t = table();
  TEST_ASSERT_EQUAL(3, t->parse(text.data(), text.size()));
  TEST_ASSERT_EQUAL(0, t->activate(kNow, 1800000000));
  rules::RewriteView v[8];
  TEST_ASSERT_EQUAL(3, t->list(v, 8, kNow));
  TEST_ASSERT_EQUAL_STRING("good.home", v[0].domain);
  TEST_ASSERT_EQUAL_STRING("10.0.0.1", v[0].target);
  TEST_ASSERT_EQUAL_STRING("spaced.home", v[1].domain);
  TEST_ASSERT_EQUAL_STRING("last.home", v[2].domain);
  // Parsing replaces the table; empty text empties it.
  TEST_ASSERT_EQUAL(0, t->parse("", 0));
  TEST_ASSERT_EQUAL(0, t->size());
}

static void test_parse_stops_at_capacity() {
  std::string text;
  for (size_t i = 0; i < RewriteTable::kMax + 10; i++)
    text += "h" + std::to_string(i) + ".home 10.0.0.1 1800000100\n";
  auto t = table();
  TEST_ASSERT_EQUAL(RewriteTable::kMax, t->parse(text.data(), text.size()));
}

static void test_serialize_needs_clock_for_active_entries() {
  auto t = table();
  t->add("a.home", "10.0.0.1", 60, kNow);
  bool ok = true;
  TEST_ASSERT_EQUAL_STRING("", save(*t, kNow, false, 0, &ok).c_str());
  TEST_ASSERT_FALSE(ok);
  // Once it expired there is nothing whose time is unknown.
  save(*t, kNow + 60 * kMin, false, 0, &ok);
  TEST_ASSERT_TRUE(ok);
  // A full table fits the documented maximum text size (longest names everywhere).
  auto big = table();
  const std::string l63(63, 'a');
  for (size_t i = 0; i < RewriteTable::kMax; i++) {
    std::string d = l63 + "." + l63 + "." + l63 + "." + std::string(57, 'b') + std::to_string(1000 + i);
    std::string target = l63 + "." + l63 + "." + l63 + "." + std::string(61, 'c');
    TEST_ASSERT_EQUAL(253, d.size());
    d = "*." + d;
    expectStatus(RewriteStatus::kAdded, big->add(d.c_str(), target.c_str(), 60, kNow), "big");
  }
  const std::string text = save(*big, kNow, true, 1800000000, &ok);
  TEST_ASSERT_TRUE(ok);
  auto back = table();
  TEST_ASSERT_EQUAL(RewriteTable::kMax, back->parse(text.data(), text.size()));
}

// ---------------------------------------------------------------------------
// Replies

static RewriteAnswer resolved(RewriteTable& t, const char* name) {
  RewriteAnswer rw;
  TEST_ASSERT_TRUE_MESSAGE(resolve(t, name, rw), name);
  return rw;
}

static void test_address_replies_by_type() {
  auto t = table();
  t->add("nas.home", "192.168.1.20", 60, kNow);
  const RewriteAnswer rw = resolved(*t, "nas.home");

  Reply r = reply(query("NAS.home", dns::kTypeA, {0xBEEF, 0x0110}), rw);  // RD + CD
  TEST_ASSERT_EQUAL_HEX16(0xBEEF, r.id);
  TEST_ASSERT_EQUAL_HEX16(0x8190, r.flags);  // QR RD RA CD; AA/AD/TC clear; NOERROR
  TEST_ASSERT_EQUAL(1, r.qd);
  TEST_ASSERT_EQUAL_STRING("NAS.home", r.qname.c_str());  // echoed as asked (DNS 0x20)
  TEST_ASSERT_EQUAL(1, r.an);
  TEST_ASSERT_EQUAL(0, r.ns);
  TEST_ASSERT_EQUAL(0, r.ar);
  TEST_ASSERT_EQUAL_STRING("192.168.1.20", r.answers[0].data.c_str());
  TEST_ASSERT_EQUAL_UINT32(30, r.answers[0].ttl);

  // No IPv6 rewrite: AAAA gets NODATA + SOA, so the real AAAA can't bypass the rewrite.
  for (uint16_t type : {dns::kTypeAaaa, dns::kTypeHttps, dns::kTypeTxt, uint16_t(15), dns::kTypeCname}) {
    r = reply(query("nas.home", type), rw);
    TEST_ASSERT_EQUAL(0, r.rcode());
    TEST_ASSERT_EQUAL(0, r.an);
    TEST_ASSERT_EQUAL(1, r.ns);
    TEST_ASSERT_EQUAL(dns::kTypeSoa, r.authority[0].type);
    TEST_ASSERT_EQUAL_STRING("nas.home", r.authority[0].name.c_str());
    TEST_ASSERT_EQUAL_UINT32(30, r.authority[0].ttl);
  }
  t->add("nas.home", "fd00::20", 60, kNow);
  r = reply(query("nas.home", dns::kTypeAaaa), resolved(*t, "nas.home"));
  TEST_ASSERT_EQUAL(1, r.an);
  TEST_ASSERT_EQUAL(dns::kTypeAaaa, r.answers[0].type);
  TEST_ASSERT_EQUAL_STRING("fd00::20", r.answers[0].data.c_str());
}

static void test_edns_and_ad_and_truncation() {
  auto t = table();
  t->add("nas.home", "192.168.1.20", 60, kNow);
  testdns::QueryOpts o;
  o.edns = true;
  o.dnssecOk = true;
  o.flags = 0x0120;  // RD + AD: still never AD for a synthesized answer
  Reply r = reply(query("nas.home", dns::kTypeA, o), resolved(*t, "nas.home"));
  TEST_ASSERT_EQUAL(0, r.flags & dns::flag::kAd);
  TEST_ASSERT_EQUAL(1, r.ar);
  TEST_ASSERT_EQUAL(dns::kTypeOpt, r.additional[0].type);
  TEST_ASSERT_EQUAL_UINT32(0x8000, r.additional[0].ttl & 0xFFFF);  // DO echoed

  // A reply bigger than the client's UDP size gets TC=1 and empty sections.
  Bytes up;
  testdns::ResponseBuilder b(0x1111, "big.example.com", dns::kTypeTxt);
  b.answerTxt(300, 700);
  up = b.build();
  t->add("txt.home", "big.example.com", 60, kNow);
  const RewriteAnswer rw = resolved(*t, "txt.home");
  r = reply(query("txt.home", dns::kTypeTxt), rw, &up, 512);
  TEST_ASSERT_TRUE(r.flags & dns::flag::kTc);
  TEST_ASSERT_EQUAL(0, r.an);
  TEST_ASSERT_EQUAL(0, r.ns);
  r = reply(query("txt.home", dns::kTypeTxt), rw, &up, 4096);  // TCP: all of it
  TEST_ASSERT_FALSE(r.flags & dns::flag::kTc);
  TEST_ASSERT_EQUAL(2, r.an);

  // A buffer too small for the records also truncates instead of failing.
  uint8_t small[120];
  const dns::Query q = query("txt.home", dns::kTypeTxt);
  const size_t n = dns::buildRewriteReply(q, rw, up.data(), up.size(), 65535, small, sizeof(small));
  TEST_ASSERT_TRUE(n > 0);
  r = decode(small, n);
  TEST_ASSERT_TRUE(r.flags & dns::flag::kTc);
  TEST_ASSERT_EQUAL(0, r.rcode());
}

static void test_local_chain_replies() {
  auto t = table();
  t->add("app.test", "web.home", 60, kNow);
  t->add("web.home", "192.168.1.9", 60, kNow);
  const RewriteAnswer rw = resolved(*t, "app.test");
  Reply r = reply(query("app.test", dns::kTypeA), rw);
  TEST_ASSERT_EQUAL(2, r.an);
  TEST_ASSERT_EQUAL(dns::kTypeCname, r.answers[0].type);
  TEST_ASSERT_EQUAL_STRING("app.test", r.answers[0].name.c_str());
  TEST_ASSERT_EQUAL_STRING("web.home", r.answers[0].data.c_str());
  TEST_ASSERT_EQUAL(dns::kTypeA, r.answers[1].type);
  TEST_ASSERT_EQUAL_STRING("web.home", r.answers[1].name.c_str());
  TEST_ASSERT_EQUAL_STRING("192.168.1.9", r.answers[1].data.c_str());
  // AAAA: the CNAME, then NODATA (SOA) for the target.
  r = reply(query("app.test", dns::kTypeAaaa), rw);
  TEST_ASSERT_EQUAL(1, r.an);
  TEST_ASSERT_EQUAL(1, r.ns);
  TEST_ASSERT_EQUAL_STRING("web.home", r.authority[0].name.c_str());
  // A CNAME query gets the chain only.
  r = reply(query("app.test", dns::kTypeCname), rw);
  TEST_ASSERT_EQUAL(1, r.an);
  TEST_ASSERT_EQUAL(0, r.ns);
}

static void test_loop_answer_is_servfail() {
  RewriteAnswer rw;
  rw.clear();
  rw.end = RewriteAnswer::End::kLoop;
  Reply r = reply(query("a.home", dns::kTypeA, {0x4242}), rw);
  TEST_ASSERT_EQUAL(2, r.rcode());
  TEST_ASSERT_EQUAL_HEX16(0x4242, r.id);
  TEST_ASSERT_EQUAL_STRING("a.home", r.qname.c_str());
}

// Upstream answer for "restrict.youtube.com" with a CNAME chain, compressed names
// everywhere, a big TTL and an OPT (stripped in practice, but harmless here).
static Bytes upstreamChain(uint16_t rcode = 0) {
  Bytes b;
  testdns::put16(b, 0x7777);
  testdns::put16(b, static_cast<uint16_t>(0x8180 | rcode));
  testdns::put16(b, 1);
  testdns::put16(b, rcode ? 0 : 2);
  testdns::put16(b, 1);
  testdns::put16(b, 0);
  testdns::putName(b, "restrict.youtube.com");  // offset 12
  testdns::put16(b, dns::kTypeA);
  testdns::put16(b, 1);
  if (!rcode) {
    // restrict.youtube.com CNAME l.youtube.com ("l" + a pointer into the question).
    testdns::put16(b, 0xC00C);
    testdns::put16(b, dns::kTypeCname);
    testdns::put16(b, 1);
    testdns::put32(b, 86400);
    testdns::put16(b, 4);
    const size_t target = b.size();
    b.push_back(1);
    b.push_back('l');
    testdns::put16(b, 0xC000 | 21);  // -> "youtube.com" inside the question
    // A record owned by the CNAME target (pointer into the previous RDATA).
    testdns::put16(b, static_cast<uint16_t>(0xC000 | target));
    testdns::put16(b, dns::kTypeA);
    testdns::put16(b, 1);
    testdns::put32(b, 0x80000000u);  // > 2^31-1: treated as 0
    testdns::put16(b, 4);
    b.insert(b.end(), {216, 239, 38, 120});
  }
  // Authority: SOA with compressed MNAME/RNAME.
  testdns::put16(b, 0xC000 | 21);  // youtube.com
  testdns::put16(b, dns::kTypeSoa);
  testdns::put16(b, 1);
  testdns::put32(b, 600);
  const size_t soaLen = b.size();
  testdns::put16(b, 0);
  const size_t soaStart = b.size();
  b.push_back(3);
  b.insert(b.end(), {'n', 's', '1'});
  testdns::put16(b, 0xC000 | 21);
  testdns::put16(b, 0xC000 | 21);
  for (int i = 0; i < 5; i++) testdns::put32(b, 300);
  const size_t l = b.size() - soaStart;
  b[soaLen] = static_cast<uint8_t>(l >> 8);
  b[soaLen + 1] = static_cast<uint8_t>(l);
  return b;
}

static void test_forwarded_chain_reply_decompresses_and_caps_ttls() {
  auto t = table();
  t->add("yt.home", "Restrict.YouTube.com", 60, kNow);
  const RewriteAnswer rw = resolved(*t, "yt.home");
  dns::Query q = query("yt.home", dns::kTypeA, {0x0102});
  dns::Query tq;
  TEST_ASSERT_TRUE(dns::rewriteTargetQuery(q, rw, tq));
  TEST_ASSERT_EQUAL_STRING("restrict.youtube.com", tq.qname);
  TEST_ASSERT_EQUAL(20, tq.qnameLen);
  TEST_ASSERT_EQUAL(22, tq.qnameWireLen);
  TEST_ASSERT_EQUAL(q.id, tq.id);
  TEST_ASSERT_EQUAL(q.qtype, tq.qtype);

  const Bytes up = upstreamChain();
  Reply r = reply(q, rw, &up);
  TEST_ASSERT_EQUAL_HEX16(0x0102, r.id);
  TEST_ASSERT_EQUAL(0, r.rcode());
  TEST_ASSERT_EQUAL_STRING("yt.home", r.qname.c_str());
  TEST_ASSERT_EQUAL(3, r.an);
  TEST_ASSERT_EQUAL(1, r.ns);
  TEST_ASSERT_EQUAL_STRING("yt.home", r.answers[0].name.c_str());
  TEST_ASSERT_EQUAL_STRING("restrict.youtube.com", r.answers[0].data.c_str());
  TEST_ASSERT_EQUAL_STRING("restrict.youtube.com", r.answers[1].name.c_str());
  TEST_ASSERT_EQUAL_STRING("l.youtube.com", r.answers[1].data.c_str());
  TEST_ASSERT_EQUAL_UINT32(30, r.answers[1].ttl);  // 86400 capped
  TEST_ASSERT_EQUAL_STRING("l.youtube.com", r.answers[2].name.c_str());
  TEST_ASSERT_EQUAL_STRING("216.239.38.120", r.answers[2].data.c_str());
  TEST_ASSERT_EQUAL_UINT32(0, r.answers[2].ttl);  // bogus TTL -> 0
  TEST_ASSERT_EQUAL(dns::kTypeSoa, r.authority[0].type);
  TEST_ASSERT_EQUAL_STRING("youtube.com", r.authority[0].name.c_str());
  // SOA RDATA rewritten without pointers: "ns1.youtube.com" "youtube.com" + 20 bytes.
  TEST_ASSERT_EQUAL(17 + 13 + 20, r.authority[0].raw.size());
  for (size_t i = 0; i < 30; i++) TEST_ASSERT_TRUE(r.authority[0].raw[i] < 0xC0);

  // NXDOMAIN for the target: the CNAME plus NXDOMAIN and the SOA (RFC 6604).
  const Bytes nx = upstreamChain(3);
  r = reply(q, rw, &nx);
  TEST_ASSERT_EQUAL(3, r.rcode());
  TEST_ASSERT_EQUAL(1, r.an);
  TEST_ASSERT_EQUAL(1, r.ns);

  // A CNAME query never needs the target's records.
  r = reply(query("yt.home", dns::kTypeCname), rw);
  TEST_ASSERT_EQUAL(1, r.an);
  TEST_ASSERT_EQUAL(0, r.ns);
}

static void test_forwarded_reply_rejects_bad_upstream_answers() {
  auto t = table();
  t->add("yt.home", "restrict.youtube.com", 60, kNow);
  const RewriteAnswer rw = resolved(*t, "yt.home");
  const dns::Query q = query("yt.home", dns::kTypeA);
  const Bytes good = upstreamChain();
  std::vector<Bytes> bad;
  bad.push_back(Bytes(good.begin(), good.begin() + 11));  // short header
  {
    Bytes b = good;
    b[3] = (b[3] & 0xF0) | 2;  // SERVFAIL
    bad.push_back(b);
  }
  {
    Bytes b = good;
    b[3] = (b[3] & 0xF0) | 5;  // REFUSED
    bad.push_back(b);
  }
  {
    Bytes b = good;
    b[2] &= 0x7F;  // not a response
    bad.push_back(b);
  }
  {
    Bytes b = good;
    b[5] = 2;  // QDCOUNT 2
    bad.push_back(b);
  }
  {
    Bytes b = good;
    b[7] = 9;  // more answers than present
    bad.push_back(b);
  }
  {
    Bytes b = good;
    b.resize(b.size() - 3);  // truncated SOA
    bad.push_back(b);
  }
  {
    Bytes b = good;
    b[good.size() - 28] = 0xC0;  // SOA MNAME turned into a pointer to itself
    b[good.size() - 27] = static_cast<uint8_t>(good.size() - 28);
    bad.push_back(b);
  }
  for (size_t i = 0; i < bad.size(); i++) {
    const Reply r = reply(q, rw, &bad[i]);
    TEST_ASSERT_EQUAL_MESSAGE(2, r.rcode(), std::to_string(i).c_str());
    TEST_ASSERT_EQUAL_STRING("yt.home", r.qname.c_str());
    TEST_ASSERT_EQUAL(0, r.an);
  }
  // A CNAME RDATA with trailing bytes (rdlen longer than the name) is malformed.
  Bytes b = good;
  const size_t cnameRdlen = 12 + 22 + 4 + 2 + 8;  // question, then owner ptr + type/class/ttl
  TEST_ASSERT_EQUAL(4, b[cnameRdlen + 1]);
  b[cnameRdlen + 1] = 2;  // rdata cut short: name runs past it
  TEST_ASSERT_EQUAL(2, reply(q, rw, &b).rcode());
}

static void test_other_rdata_types_copied_and_decompressed() {
  // MX with a compressed exchange name, and an HTTPS record copied byte for byte.
  Bytes b;
  testdns::put16(b, 1);
  testdns::put16(b, 0x8180);
  testdns::put16(b, 1);
  testdns::put16(b, 2);
  testdns::put16(b, 0);
  testdns::put16(b, 0);
  testdns::putName(b, "mail.example.com");
  testdns::put16(b, 15);
  testdns::put16(b, 1);
  testdns::put16(b, 0xC00C);
  testdns::put16(b, 15);
  testdns::put16(b, 1);
  testdns::put32(b, 10);
  testdns::put16(b, 2 + 2 + 2);
  testdns::put16(b, 5);
  b.push_back(1);
  b.push_back('m');
  testdns::put16(b, 0xC00C);
  testdns::put16(b, 0xC00C);
  testdns::put16(b, dns::kTypeHttps);
  testdns::put16(b, 1);
  testdns::put32(b, 10);
  testdns::put16(b, 5);
  b.insert(b.end(), {0, 1, 0xC0, 0x0C, 0x7F});  // looks like a pointer but must stay as is
  auto t = table();
  t->add("mx.home", "mail.example.com", 60, kNow);
  const Reply r = reply(query("mx.home", 15), resolved(*t, "mx.home"), &b);
  TEST_ASSERT_EQUAL(3, r.an);
  TEST_ASSERT_EQUAL(15, r.answers[1].type);
  TEST_ASSERT_EQUAL_UINT32(10, r.answers[1].ttl);  // below the cap: unchanged
  const Bytes mx = {0,   5,   1,   'm', 4,   'm', 'a', 'i', 'l', 7,   'e',
                    'x', 'a', 'm', 'p', 'l', 'e', 3,   'c', 'o', 'm', 0};
  TEST_ASSERT_TRUE(mx == r.answers[1].raw);
  const Bytes https = {0, 1, 0xC0, 0x0C, 0x7F};
  TEST_ASSERT_TRUE(https == r.answers[2].raw);
}

static void test_target_query_edge_cases() {
  RewriteAnswer rw;
  rw.clear();
  dns::Query q = query("a.home", dns::kTypeA), tq;
  TEST_ASSERT_FALSE(dns::rewriteTargetQuery(q, rw, tq));  // no hops
  const uint8_t root[1] = {0};
  TEST_ASSERT_TRUE(rw.addHop(root, 1));
  TEST_ASSERT_FALSE(dns::rewriteTargetQuery(q, rw, tq));  // never the root
  rw.clear();
  const uint8_t badLabel[5] = {3, 'a', ' ', 'b', 0};
  rw.addHop(badLabel, 5);
  TEST_ASSERT_FALSE(dns::rewriteTargetQuery(q, rw, tq));
  // addHop limits: hop count and byte budget.
  rw.clear();
  uint8_t w[dns::kMaxNameWire];
  const size_t wl = dns::encodeName("ab.c", 4, w, sizeof(w));
  for (size_t i = 0; i < dns::kMaxRewriteHops; i++) TEST_ASSERT_TRUE(rw.addHop(w, wl));
  TEST_ASSERT_FALSE(rw.addHop(w, wl));
  TEST_ASSERT_FALSE(rw.addHop(w, 0));
}

static void test_encode_and_read_name() {
  uint8_t w[dns::kMaxNameWire];
  TEST_ASSERT_EQUAL(1, dns::encodeName("", 0, w, sizeof(w)));
  TEST_ASSERT_EQUAL(7, dns::encodeName("ab.cd", 5, w, sizeof(w)));
  TEST_ASSERT_EQUAL(0, dns::encodeName("ab.", 3, w, sizeof(w)));
  TEST_ASSERT_EQUAL(0, dns::encodeName(".ab", 3, w, sizeof(w)));
  TEST_ASSERT_EQUAL(0, dns::encodeName("a..b", 4, w, sizeof(w)));
  TEST_ASSERT_EQUAL(7, dns::encodeName("ab.cd", 5, w, 7));
  TEST_ASSERT_EQUAL(0, dns::encodeName("ab.cd", 5, w, 6));  // cap
  const std::string l64(64, 'a');
  TEST_ASSERT_EQUAL(0, dns::encodeName(l64.c_str(), l64.size(), w, sizeof(w)));
  const std::string l63(63, 'a'), n253 = l63 + "." + l63 + "." + l63 + "." + std::string(61, 'b');
  TEST_ASSERT_EQUAL(255, dns::encodeName(n253.c_str(), n253.size(), w, sizeof(w)));
  const std::string n254 = n253 + "b";
  TEST_ASSERT_EQUAL(0, dns::encodeName(n254.c_str(), n254.size(), w, sizeof(w)));

  // readName: pointers forward/backward, loops, overruns.
  const uint8_t loop[] = {0xC0, 0x00};
  size_t wl;
  TEST_ASSERT_EQUAL(0, dns::readName(loop, sizeof(loop), 0, w, wl));
  const uint8_t overrun[] = {5, 'a', 'b'};
  TEST_ASSERT_EQUAL(0, dns::readName(overrun, sizeof(overrun), 0, w, wl));
  const uint8_t ptrOut[] = {0xC0, 0x40};
  TEST_ASSERT_EQUAL(0, dns::readName(ptrOut, sizeof(ptrOut), 0, w, wl));
  const uint8_t halfPtr[] = {1, 'a', 0xC0};
  TEST_ASSERT_EQUAL(0, dns::readName(halfPtr, sizeof(halfPtr), 0, w, wl));
  const uint8_t badType[] = {0x40, 0};
  TEST_ASSERT_EQUAL(0, dns::readName(badType, sizeof(badType), 0, w, wl));
  const uint8_t ok[] = {1, 'B', 0, 1, 'a', 0xC0, 0x00};  // "a" + ptr -> "B"
  TEST_ASSERT_EQUAL(7, dns::readName(ok, sizeof(ok), 3, w, wl));
  TEST_ASSERT_EQUAL(5, wl);
  TEST_ASSERT_EQUAL_STRING("a.B", wireText(w, wl).c_str());  // case kept
  // A pointer chain that builds a name longer than 255 bytes.
  Bytes longChain;
  for (int i = 0; i < 5; i++) {
    longChain.push_back(63);
    longChain.insert(longChain.end(), 63, 'x');
  }
  longChain.push_back(0);
  TEST_ASSERT_EQUAL(0, dns::readName(longChain.data(), longChain.size(), 0, w, wl));
}

static void test_rewrite_replies_echo_the_question_case() {
  auto t = table();
  t->add("nas.home", "192.168.1.20", 60, kNow);
  const dns::Query q = query("NAS.Home", dns::kTypeA);
  uint8_t out[512];
  const size_t n = dns::buildRewriteReply(q, resolved(*t, "nas.home"), nullptr, 0, 512, out, sizeof(out));
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL_MEMORY("\x03NAS\x04Home", out + dns::kHeaderSize, 9);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_rewrite_replies_echo_the_question_case);
  RUN_TEST(test_domain_validation);
  RUN_TEST(test_ipv4_parsing);
  RUN_TEST(test_ipv6_parsing_and_canonical_text);
  RUN_TEST(test_target_validation);
  RUN_TEST(test_add_update_conflict_remove);
  RUN_TEST(test_duration_limits);
  RUN_TEST(test_table_full_and_expired_slots_reused);
  RUN_TEST(test_exact_beats_wildcard_and_longest_wildcard_wins);
  RUN_TEST(test_expiry_boundaries_and_ttl);
  RUN_TEST(test_alias_chains);
  RUN_TEST(test_loops_are_refused_and_table_unchanged);
  RUN_TEST(test_chain_longer_than_limit_is_refused);
  RUN_TEST(test_serialize_parse_round_trip_and_activation);
  RUN_TEST(test_activation_drops_expired_and_future_entries);
  RUN_TEST(test_parse_skips_bad_lines);
  RUN_TEST(test_parse_stops_at_capacity);
  RUN_TEST(test_serialize_needs_clock_for_active_entries);
  RUN_TEST(test_address_replies_by_type);
  RUN_TEST(test_edns_and_ad_and_truncation);
  RUN_TEST(test_local_chain_replies);
  RUN_TEST(test_loop_answer_is_servfail);
  RUN_TEST(test_forwarded_chain_reply_decompresses_and_caps_ttls);
  RUN_TEST(test_forwarded_reply_rejects_bad_upstream_answers);
  RUN_TEST(test_other_rdata_types_copied_and_decompressed);
  RUN_TEST(test_target_query_edge_cases);
  RUN_TEST(test_encode_and_read_name);
  return UNITY_END();
}
