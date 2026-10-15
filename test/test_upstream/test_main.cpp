// Tests for lib/core/upstream: health state machine, DoT/DoH framing, and the
// forwarder's fallback chain, hedging, deadlines, pipelining and plain fallback.

#include <unity.h>

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "fakes/capturing_logger.h"
#include "fakes/dns_builder.h"
#include "fakes/fake_clock.h"
#include "fakes/fake_random.h"
#include "fakes/fake_transport.h"
#include "upstream/forwarder.h"
#include "upstream/framing.h"
#include "upstream/health.h"

using namespace testdns;
using upstream::Forwarder;
using upstream::HealthState;
using upstream::IoStatus;
using upstream::TransportKind;

// --- sink -------------------------------------------------------------------------

struct Result {
  uint32_t token;
  bool ok;
  bool authenticated;
  Bytes answer;
};

class RecordingSink final : public upstream::IForwarderSink {
 public:
  void onAnswer(uint32_t token, const dns::Query&, const uint8_t* answer, size_t len,
                const dns::ResponseInfo&, bool authenticated) override {
    results.push_back({token, true, authenticated, Bytes(answer, answer + len)});
  }
  void onFailure(uint32_t token, const dns::Query&) override { results.push_back({token, false, false, {}}); }
  std::vector<Result> results;
};

// --- fixture ----------------------------------------------------------------------

static FakeClock fakeClock;
static FakeRandom fakeRandom;
static CapturingLogger logger;
static RecordingSink sink;
static std::unique_ptr<FakeTransport> dot1, dot2, doh, plain;
static std::unique_ptr<Forwarder> fwd;

static void build(upstream::ForwarderConfig cfg = {}) {
  upstream::ITransport* chain[] = {dot1.get(), dot2.get(), doh.get(), plain.get()};
  fwd = std::make_unique<Forwarder>(cfg, chain, 4, fakeClock, fakeRandom, logger, sink);
}

void setUp() {
  fakeClock = FakeClock{};
  fakeRandom = FakeRandom{};
  logger.lines.clear();
  sink.results.clear();
  dot1 = std::make_unique<FakeTransport>("cf-dot", TransportKind::kDoT, true, true);
  dot2 = std::make_unique<FakeTransport>("q9-dot", TransportKind::kDoT, true, true);
  doh = std::make_unique<FakeTransport>("cf-doh", TransportKind::kDoH, true, false);
  plain = std::make_unique<FakeTransport>("q9-udp", TransportKind::kUdp, false, true);
  build();
}
void tearDown() {
  fwd.reset();
}

static dns::Query query(const std::string& name, uint16_t id = 0x1111) {
  QueryOpts o;
  o.id = id;
  Bytes pkt = makeQuery(name, dns::kTypeA, o);
  dns::Query q;
  dns::parseQuery(pkt.data(), pkt.size(), q);
  return q;
}

static void downAll(FakeTransport& t) {
  t.mode = FakeTransport::Mode::kRefuseConnect;
}

// --- health -----------------------------------------------------------------------

static void test_health_goes_down_after_three_failures_and_backs_off() {
  upstream::UpstreamHealth h;
  TEST_ASSERT_EQUAL(static_cast<int>(HealthState::kUnknown), static_cast<int>(h.state()));
  h.onFailure(1000, 0);
  TEST_ASSERT_EQUAL(static_cast<int>(HealthState::kDegraded), static_cast<int>(h.state()));
  h.onFailure(1000, 0);
  h.onFailure(1000, 400);  // jitter: 1000 ms +/- 200 -> 800 + 400 % 401
  TEST_ASSERT_EQUAL(static_cast<int>(HealthState::kDown), static_cast<int>(h.state()));
  TEST_ASSERT_EQUAL_UINT32(1000, h.backoffMs());
  TEST_ASSERT_FALSE(h.available(1000 + 1199));
  TEST_ASSERT_TRUE(h.available(1000 + 1200));
}

static void test_health_probe_failure_doubles_backoff_and_success_recovers() {
  upstream::UpstreamHealth h;
  for (int i = 0; i < 3; i++) h.onFailure(0, 0);
  for (uint32_t expect : {2000u, 4000u, 8000u}) {
    h.beginProbe();
    TEST_ASSERT_EQUAL(static_cast<int>(HealthState::kProbing), static_cast<int>(h.state()));
    h.onFailure(0, 0);
    TEST_ASSERT_EQUAL_UINT32(expect, h.backoffMs());
  }
  h.beginProbe();
  h.onSuccess(42);
  TEST_ASSERT_EQUAL(static_cast<int>(HealthState::kUp), static_cast<int>(h.state()));
  TEST_ASSERT_EQUAL_UINT32(0, h.consecutiveFailures());
  TEST_ASSERT_EQUAL_UINT32(42, h.stats().lastLatencyMs);
}

static void test_health_backoff_is_capped() {
  upstream::HealthConfig cfg;
  cfg.jitterPercent = 0;
  upstream::UpstreamHealth h(cfg);
  for (int i = 0; i < 3; i++) h.onFailure(0, 0);
  for (int i = 0; i < 20; i++) {
    h.beginProbe();
    h.onFailure(0, 0);
  }
  TEST_ASSERT_EQUAL_UINT32(300000, h.backoffMs());
  TEST_ASSERT_TRUE(h.nextProbeMs() == 300000);
}

// --- framing ----------------------------------------------------------------------

static void test_stream_deframer_handles_split_and_coalesced_frames() {
  uint8_t buf[64], out[64], framed[64];
  upstream::StreamDeframer d(buf, sizeof(buf));
  const uint8_t m1[] = {1, 2, 3}, m2[] = {9, 8};
  size_t n1 = upstream::frameForStream(m1, 3, framed, sizeof(framed));
  size_t n2 = upstream::frameForStream(m2, 2, framed + n1, sizeof(framed) - n1);
  TEST_ASSERT_TRUE(d.feed(framed, 1));  // half a length prefix
  TEST_ASSERT_EQUAL(0, d.next(out, sizeof(out)));
  TEST_ASSERT_TRUE(d.feed(framed + 1, n1 + n2 - 1));  // rest + whole second frame
  TEST_ASSERT_EQUAL(3, d.next(out, sizeof(out)));
  TEST_ASSERT_EQUAL_HEX8_ARRAY(m1, out, 3);
  TEST_ASSERT_EQUAL(2, d.next(out, sizeof(out)));
  TEST_ASSERT_EQUAL_HEX8_ARRAY(m2, out, 2);
  TEST_ASSERT_EQUAL(0, d.next(out, sizeof(out)));
}

static void test_stream_deframer_rejects_oversized_frames() {
  uint8_t buf[16], out[16];
  upstream::StreamDeframer d(buf, sizeof(buf));
  const uint8_t huge[] = {0x10, 0x00};  // claims 4096 bytes
  TEST_ASSERT_FALSE(d.feed(huge, 2));
  TEST_ASSERT_TRUE(d.failed());
  TEST_ASSERT_EQUAL(0, d.next(out, sizeof(out)));
  uint8_t small[2];
  TEST_ASSERT_EQUAL(0, upstream::frameForStream(out, 1, small, sizeof(small)));
}

static void test_doh_request_head() {
  uint8_t out[512];
  size_t n = upstream::buildDohRequestHead("cloudflare-dns.com", "/dns-query", 128, out, sizeof(out));
  std::string s(reinterpret_cast<char*>(out), n);
  TEST_ASSERT_TRUE(s.rfind("POST /dns-query HTTP/1.1\r\n", 0) == 0);
  TEST_ASSERT_TRUE(s.find("Host: cloudflare-dns.com\r\n") != std::string::npos);
  TEST_ASSERT_TRUE(s.find("Content-Type: application/dns-message\r\n") != std::string::npos);
  TEST_ASSERT_TRUE(s.find("Content-Length: 128\r\n") != std::string::npos);
  TEST_ASSERT_TRUE(s.size() >= 4 && s.compare(s.size() - 4, 4, "\r\n\r\n") == 0);
  TEST_ASSERT_EQUAL(0, upstream::buildDohRequestHead("h", "/p", 1, out, 20));
}

static upstream::HttpResponseParser::State feedAll(upstream::HttpResponseParser& p, const std::string& s,
                                                   size_t step) {
  upstream::HttpResponseParser::State st = p.state();
  for (size_t i = 0; i < s.size(); i += step) {
    size_t n = std::min(step, s.size() - i);
    st = p.feed(reinterpret_cast<const uint8_t*>(s.data() + i), n);
  }
  return st;
}

static void test_http_parser_complete_response_byte_by_byte() {
  uint8_t buf[512];
  upstream::HttpResponseParser p(buf, sizeof(buf));
  std::string r =
      "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
      "content-length: 5\r\nConnection: keep-alive\r\n\r\nABCDE";
  TEST_ASSERT_EQUAL(static_cast<int>(upstream::HttpResponseParser::State::kComplete),
                    static_cast<int>(feedAll(p, r, 1)));
  TEST_ASSERT_EQUAL(200, p.status());
  TEST_ASSERT_TRUE(p.keepAlive());
  TEST_ASSERT_TRUE(p.dnsMessageType());
  TEST_ASSERT_EQUAL(5, p.bodyLen());
  TEST_ASSERT_EQUAL_MEMORY("ABCDE", p.body(), 5);
  p.reset();
  r = "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  TEST_ASSERT_EQUAL(static_cast<int>(upstream::HttpResponseParser::State::kComplete),
                    static_cast<int>(feedAll(p, r, 7)));
  TEST_ASSERT_EQUAL(505, p.status());
  TEST_ASSERT_FALSE(p.keepAlive());
}

static void test_http_parser_rejects_bad_input() {
  uint8_t buf[256];
  upstream::HttpResponseParser p(buf, sizeof(buf));
  const char* bad[] = {
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",  // chunked unsupported
      "HTTP/1.1 200 OK\r\nContent-Type: x\r\n\r\n",             // no length
      "HTTP/1.1 2x0 OK\r\nContent-Length: 1\r\n\r\nA",          // bad status
      "HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n",    // absurd length
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nA",
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nAB",  // trailing junk
      "SMTP ready\r\n\r\n",
  };
  for (const char* b : bad) {
    p.reset();
    TEST_ASSERT_EQUAL_MESSAGE(static_cast<int>(upstream::HttpResponseParser::State::kError),
                              static_cast<int>(feedAll(p, b, 3)), b);
  }
  p.reset();
  std::string big = "HTTP/1.1 200 OK\r\nContent-Length: 300\r\n\r\n";  // body > buffer
  TEST_ASSERT_EQUAL(static_cast<int>(upstream::HttpResponseParser::State::kError),
                    static_cast<int>(feedAll(p, big, 50)));
}

// --- forwarder ----------------------------------------------------------------------

static void test_answers_from_primary_dot_with_opt_stripped() {
  TEST_ASSERT_TRUE(fwd->submit(7, query("Example.com")));
  fwd->poll(0);
  TEST_ASSERT_EQUAL(1, sink.results.size());
  const Result& r = sink.results[0];
  TEST_ASSERT_TRUE(r.ok);
  TEST_ASSERT_EQUAL_UINT32(7, r.token);
  TEST_ASSERT_TRUE(r.authenticated);
  TEST_ASSERT_EQUAL(0, get16(r.answer, 10));  // OPT removed before the sink
  TEST_ASSERT_EQUAL(1, dot1->sent.size());
  TEST_ASSERT_EQUAL(0, dot1->sent[0].size() % 128);        // padded query
  TEST_ASSERT_NOT_EQUAL(0x1111, get16(dot1->sent[0], 0));  // fresh upstream ID
  TEST_ASSERT_EQUAL(0, dot2->sent.size());
  TEST_ASSERT_EQUAL(static_cast<int>(HealthState::kUp), static_cast<int>(fwd->upstreamStatus(0).state));
  TEST_ASSERT_EQUAL(0, fwd->inFlight());
}

static void test_falls_through_to_next_upstream_when_connect_fails() {
  downAll(*dot1);
  fwd->submit(1, query("a.example"));
  fwd->poll(0);
  TEST_ASSERT_EQUAL(1, sink.results.size());
  TEST_ASSERT_TRUE(sink.results[0].ok);
  TEST_ASSERT_EQUAL(1, dot2->sent.size());
  TEST_ASSERT_EQUAL(static_cast<int>(HealthState::kDegraded), static_cast<int>(fwd->upstreamStatus(0).state));
}

static void test_down_upstream_is_skipped_until_backoff_then_probed() {
  downAll(*dot1);
  for (int i = 0; i < 3; i++) {
    fwd->submit(i, query("q" + std::to_string(i) + ".example"));
    fwd->poll(0);
  }
  TEST_ASSERT_EQUAL(static_cast<int>(HealthState::kDown), static_cast<int>(fwd->upstreamStatus(0).state));
  const int connectsWhenDown = dot1->connects;
  fwd->submit(10, query("skip.example"));
  fwd->poll(0);
  TEST_ASSERT_EQUAL(connectsWhenDown, dot1->connects);  // not even attempted
  dot1->mode = FakeTransport::Mode::kAnswer;            // primary recovers
  fakeClock.advanceMs(1300);                            // > 1 s backoff + jitter
  fwd->submit(11, query("probe.example"));
  fwd->poll(0);
  TEST_ASSERT_EQUAL(connectsWhenDown + 1, dot1->connects);
  TEST_ASSERT_EQUAL(static_cast<int>(HealthState::kUp), static_cast<int>(fwd->upstreamStatus(0).state));
  TEST_ASSERT_EQUAL(1, logger.count(hal::LogLevel::kInfo, "cf-dot: probing -> up"));
}

static void test_slow_upstream_is_hedged_and_late_reply_ignored() {
  dot1->holdReplies = true;  // primary answers, but late
  fwd->submit(5, query("slow.example"));
  fwd->poll(0);
  TEST_ASSERT_EQUAL(0, sink.results.size());
  fakeClock.advanceMs(1199);
  fwd->poll(0);
  TEST_ASSERT_EQUAL(0, dot2->sent.size());
  fakeClock.advanceMs(1);
  fwd->poll(0);  // hedge: re-sent to dot2, which answers immediately
  TEST_ASSERT_EQUAL(1, dot2->sent.size());
  fwd->poll(0);
  TEST_ASSERT_EQUAL(1, sink.results.size());
  TEST_ASSERT_TRUE(sink.results[0].ok);
  dot1->release();
  fwd->poll(0);  // the late primary answer must not produce a second result
  TEST_ASSERT_EQUAL(1, sink.results.size());
}

static void test_deadline_gives_servfail() {
  dot1->mode = dot2->mode = doh->mode = FakeTransport::Mode::kSilent;
  fwd->submit(9, query("blackhole.example"));
  for (int i = 0; i < 30; i++) {
    fakeClock.advanceMs(100);
    fwd->poll(0);
  }
  TEST_ASSERT_EQUAL(1, sink.results.size());
  TEST_ASSERT_FALSE(sink.results[0].ok);
  TEST_ASSERT_EQUAL(0, fwd->inFlight());
  TEST_ASSERT_EQUAL(0, plain->sent.size());  // silence is not "Down": no plain fallback
}

static void test_plain_fallback_only_when_all_encrypted_down_and_logged_once() {
  downAll(*dot1);
  downAll(*dot2);
  downAll(*doh);
  // A failing-but-not-yet-Down encrypted chain must not leak the query in plain text.
  fwd->submit(0, query("p0.example"));
  fwd->poll(0);
  TEST_ASSERT_EQUAL(0, plain->sent.size());
  TEST_ASSERT_FALSE(sink.results.back().ok);
  TEST_ASSERT_FALSE(fwd->plainFallbackActive());
  for (int i = 1; i < 5; i++) {
    fwd->submit(i, query("p" + std::to_string(i) + ".example"));
    fwd->poll(0);
  }
  // Once all three are Down, queries go to plain UDP and are marked unauthenticated.
  TEST_ASSERT_TRUE(fwd->plainFallbackActive());
  TEST_ASSERT_TRUE(plain->sent.size() >= 1);
  TEST_ASSERT_FALSE(sink.results.back().authenticated);
  TEST_ASSERT_TRUE(sink.results.back().ok);
  TEST_ASSERT_EQUAL(1, logger.count(hal::LogLevel::kWarn, "using PLAIN DNS"));

  dot1->mode = FakeTransport::Mode::kAnswer;  // Cloudflare comes back
  fakeClock.advanceMs(1300);
  fwd->submit(99, query("back.example"));
  fwd->poll(0);
  TEST_ASSERT_TRUE(sink.results.back().authenticated);
  TEST_ASSERT_FALSE(fwd->plainFallbackActive());
  TEST_ASSERT_EQUAL(1, logger.count(hal::LogLevel::kInfo, "plain DNS fallback off"));
}

static void test_strict_mode_servfails_instead_of_plain() {
  upstream::ForwarderConfig cfg;
  cfg.allowPlainFallback = false;
  build(cfg);
  downAll(*dot1);
  downAll(*dot2);
  downAll(*doh);
  for (int i = 0; i < 5; i++) {
    fwd->submit(i, query("s" + std::to_string(i) + ".example"));
    fwd->poll(0);
  }
  TEST_ASSERT_EQUAL(0, plain->sent.size());
  TEST_ASSERT_FALSE(sink.results.back().ok);
  TEST_ASSERT_FALSE(fwd->plainFallbackActive());
}

static void test_forged_or_mismatched_replies_are_ignored() {
  dot1->responder = [](const Bytes& q) {
    dns::Query parsed;
    dns::parseQuery(q.data(), q.size(), parsed);
    // Wrong ID, then right ID but different name: neither may be accepted.
    return ResponseBuilder(static_cast<uint16_t>(get16(q, 0) + 1), parsed.qname, 1)
        .answerA(60, 6, 6, 6, 6)
        .build();
  };
  fwd->submit(1, query("bank.example"));
  dot1->inbox.push_back(ResponseBuilder(0, "evil.example", 1).answerA(60, 6, 6, 6, 6).build());
  fwd->poll(0);
  TEST_ASSERT_EQUAL(0, sink.results.size());
  TEST_ASSERT_EQUAL(1, fwd->inFlight());
}

static void test_pipelines_queries_and_matches_out_of_order_replies() {
  dot1->holdReplies = true;
  fwd->submit(1, query("one.example", 1));
  fwd->submit(2, query("two.example", 2));
  fwd->submit(3, query("three.example", 3));
  TEST_ASSERT_EQUAL(3, dot1->sent.size());  // all sent before any reply
  dot1->release(/*reversed=*/true);
  fwd->poll(0);
  TEST_ASSERT_EQUAL(3, sink.results.size());
  TEST_ASSERT_EQUAL_UINT32(3, sink.results[0].token);
  TEST_ASSERT_EQUAL_UINT32(2, sink.results[1].token);
  TEST_ASSERT_EQUAL_UINT32(1, sink.results[2].token);
  // Each answer is for the right name.
  dns::Query q3 = query("three.example");
  TEST_ASSERT_TRUE(dns::responseMatches(sink.results[0].answer.data(), sink.results[0].answer.size(),
                                        get16(sink.results[0].answer, 0), q3));
}

static void test_doh_sends_one_request_at_a_time() {
  downAll(*dot1);
  downAll(*dot2);
  for (int i = 0; i < 3; i++) {  // take both DoT upstreams Down
    fwd->submit(100 + i, query("warm" + std::to_string(i) + ".example"));
    fwd->poll(0);
  }
  sink.results.clear();
  doh->sent.clear();
  doh->holdReplies = true;
  fwd->submit(1, query("x.example"));
  fwd->submit(2, query("y.example"));
  TEST_ASSERT_EQUAL(1, doh->sent.size());
  doh->release();
  fwd->poll(0);  // first answered, second sent
  TEST_ASSERT_EQUAL(2, doh->sent.size());
  doh->release();
  fwd->poll(0);
  TEST_ASSERT_EQUAL(2, sink.results.size());
}

static void test_table_full_rejects_submit() {
  dot1->mode = FakeTransport::Mode::kSilent;
  for (size_t i = 0; i < Forwarder::kMaxInFlight; i++)
    TEST_ASSERT_TRUE(fwd->submit(static_cast<uint32_t>(i), query("f" + std::to_string(i) + ".example")));
  TEST_ASSERT_FALSE(fwd->submit(999, query("overflow.example")));
}

static void test_closed_connection_reroutes_in_flight_queries() {
  dot1->mode = FakeTransport::Mode::kCloseAfterSend;
  fwd->submit(1, query("c.example"));
  fwd->poll(0);  // dot1 reports closed -> rerouted to dot2 -> answered
  fwd->poll(0);
  TEST_ASSERT_EQUAL(1, sink.results.size());
  TEST_ASSERT_TRUE(sink.results[0].ok);
  TEST_ASSERT_EQUAL(1, dot2->sent.size());
}

static void test_malformed_reply_counts_as_failure_and_reroutes() {
  dot1->responder = [](const Bytes& q) {
    dns::Query parsed;
    dns::parseQuery(q.data(), q.size(), parsed);
    Bytes r = ResponseBuilder(get16(q, 0), parsed.qname, 1).opt().answerA(60, 1, 1, 1, 1).build();
    r[7] = 1;  // ANCOUNT 1, ARCOUNT 1: but the OPT comes first (not last)
    r[11] = 1;
    return r;
  };
  fwd->submit(1, query("m.example"));
  fwd->poll(0);
  fwd->poll(0);
  TEST_ASSERT_EQUAL(1, sink.results.size());
  TEST_ASSERT_TRUE(sink.results[0].ok);
  TEST_ASSERT_EQUAL(1, dot2->sent.size());
  TEST_ASSERT_EQUAL(1, logger.count(hal::LogLevel::kWarn, "malformed reply"));
}

static void test_idle_connections_are_closed_before_the_server_does() {
  fwd->submit(1, query("a.example"));
  fwd->poll(0);
  TEST_ASSERT_TRUE(dot1->connected());
  fakeClock.advanceMs(8999);
  fwd->poll(0);
  TEST_ASSERT_TRUE(dot1->connected());
  fakeClock.advanceMs(1);
  fwd->poll(0);
  TEST_ASSERT_FALSE(dot1->connected());
  fwd->submit(2, query("b.example"));  // reconnects lazily
  fwd->poll(0);
  TEST_ASSERT_EQUAL(2, dot1->connects);
  TEST_ASSERT_EQUAL(2, sink.results.size());
}

static void test_reply_flood_cannot_trap_poll() {
  // 1000 forged/unmatched replies queued ahead of the real answer: poll() must return
  // after a bounded amount of work, and the real answer still arrives eventually.
  dot1->holdReplies = true;
  fwd->submit(1, query("flood.example"));
  for (int i = 0; i < 1000; i++)
    dot1->inbox.push_back(ResponseBuilder(static_cast<uint16_t>(i), "junk.example", 1).build());
  dot1->release();
  fwd->poll(0);
  TEST_ASSERT_EQUAL(1001 - Forwarder::kMaxRepliesPerPoll, dot1->inbox.size());
  for (int i = 0; i < 20 && sink.results.empty(); i++) fwd->poll(0);
  TEST_ASSERT_EQUAL(1, sink.results.size());
  TEST_ASSERT_TRUE(sink.results[0].ok);
}

static void test_slow_failing_connects_respect_the_blocking_budget() {
  // Each failed connect "takes" 3 s. One call may only start a connect if it still
  // fits in maxBlockingMs (4 s), so no single call blocks long enough to trip the
  // 5 s task watchdog; the remaining upstreams are tried on later polls.
  downAll(*dot1);
  downAll(*dot2);
  downAll(*doh);
  for (FakeTransport* t : {dot1.get(), dot2.get(), doh.get()})
    t->onConnect = [] { fakeClock.advanceMs(3000); };
  uint64_t t0 = fakeClock.monotonicMs();
  fwd->submit(1, query("slow-net.example"));
  TEST_ASSERT_EQUAL(1, dot1->connects);
  TEST_ASSERT_EQUAL(0, dot2->connects);
  TEST_ASSERT_TRUE(fakeClock.monotonicMs() - t0 <= 4000);
  t0 = fakeClock.monotonicMs();
  fwd->poll(0);
  TEST_ASSERT_EQUAL(1, dot2->connects);
  TEST_ASSERT_EQUAL(0, doh->connects);
  TEST_ASSERT_TRUE(fakeClock.monotonicMs() - t0 <= 4000);
  // 6 s have passed: well beyond the 2.5 s deadline, so the client got SERVFAIL.
  TEST_ASSERT_EQUAL(1, sink.results.size());
  TEST_ASSERT_FALSE(sink.results[0].ok);
}

static void test_deadline_does_not_blame_an_upstream_that_had_no_time_to_answer() {
  // Found on hardware: a blackholed primary used up most of each query's 2.5 s budget
  // in its connect timeout, the query then reached the healthy secondary with ~0.1 s
  // left, and the expired deadline was blamed on the secondary, marking it down too
  // (about 30 s of SERVFAIL). Only blame an upstream given at least hedgeAfterMs.
  downAll(*dot1);
  dot1->onConnect = [] { fakeClock.advanceMs(2400); };
  dot2->holdReplies = true;  // healthy, but its reply has not arrived yet
  fwd->submit(1, query("late.example"));
  fwd->poll(0);                             // the retry waits for the next call (blocking budget)
  TEST_ASSERT_EQUAL(1, dot2->sent.size());  // rerouted after the failed connect
  fakeClock.advanceMs(200);                 // past the deadline, 0.2 s after sending
  fwd->poll(0);
  TEST_ASSERT_EQUAL(1, sink.results.size());
  TEST_ASSERT_FALSE(sink.results[0].ok);  // the client still gets SERVFAIL
  TEST_ASSERT_EQUAL(static_cast<int>(HealthState::kDegraded), static_cast<int>(fwd->upstreamStatus(0).state));
  TEST_ASSERT_EQUAL_UINT32(0, fwd->upstreamStatus(1).stats.failed);  // secondary not blamed
  TEST_ASSERT_NOT_EQUAL(static_cast<int>(HealthState::kDegraded),
                        static_cast<int>(fwd->upstreamStatus(1).state));
}

static void test_deadline_blames_an_upstream_that_had_time_to_answer() {
  dot1->mode = FakeTransport::Mode::kSilent;  // connected, never answers
  dot2->mode = doh->mode = FakeTransport::Mode::kSilent;
  fwd->submit(2, query("silent.example"));
  for (int i = 0; i < 30; i++) {
    fakeClock.advanceMs(100);
    fwd->poll(0);
  }
  TEST_ASSERT_EQUAL(1, sink.results.size());
  TEST_ASSERT_FALSE(sink.results[0].ok);
  uint32_t failed = 0;
  for (int u = 0; u < 3; u++) failed += fwd->upstreamStatus(u).stats.failed;
  TEST_ASSERT_TRUE(failed >= 2);  // the hedge blamed the first, the deadline the second
}

static void test_failed_doh_does_not_reconnect_for_each_queued_query() {
  // Found on hardware: DoH sends one request at a time, so further queries queue
  // behind it, already assigned to it. When its connection failed, only the in-flight
  // query was rerouted; each queued one then opened its own doomed connection to the
  // failed server (14 failed TLS attempts in ~1 s).
  downAll(*dot1);
  downAll(*dot2);
  for (int i = 0; i < 3; i++) {  // take both DoT upstreams Down
    fwd->submit(100 + i, query("warm" + std::to_string(i) + ".example"));
    fwd->poll(0);
  }
  sink.results.clear();
  doh->sent.clear();
  doh->holdReplies = true;
  for (int i = 0; i < 3; i++) fwd->submit(i, query("q" + std::to_string(i) + ".example"));
  TEST_ASSERT_EQUAL(1, doh->sent.size());  // one in flight, two queued behind it
  const int connectsBefore = doh->connects;
  doh->mode = FakeTransport::Mode::kCloseAfterSend;  // the connection dies
  fwd->poll(0);
  TEST_ASSERT_EQUAL(connectsBefore, doh->connects);  // no reconnect per queued query
  TEST_ASSERT_EQUAL(1, doh->sent.size());
  TEST_ASSERT_EQUAL(3, sink.results.size());  // all three answered (SERVFAIL), none stuck
  TEST_ASSERT_EQUAL(0, fwd->inFlight());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_health_goes_down_after_three_failures_and_backs_off);
  RUN_TEST(test_health_probe_failure_doubles_backoff_and_success_recovers);
  RUN_TEST(test_health_backoff_is_capped);
  RUN_TEST(test_stream_deframer_handles_split_and_coalesced_frames);
  RUN_TEST(test_stream_deframer_rejects_oversized_frames);
  RUN_TEST(test_doh_request_head);
  RUN_TEST(test_http_parser_complete_response_byte_by_byte);
  RUN_TEST(test_http_parser_rejects_bad_input);
  RUN_TEST(test_answers_from_primary_dot_with_opt_stripped);
  RUN_TEST(test_falls_through_to_next_upstream_when_connect_fails);
  RUN_TEST(test_down_upstream_is_skipped_until_backoff_then_probed);
  RUN_TEST(test_slow_upstream_is_hedged_and_late_reply_ignored);
  RUN_TEST(test_deadline_gives_servfail);
  RUN_TEST(test_plain_fallback_only_when_all_encrypted_down_and_logged_once);
  RUN_TEST(test_strict_mode_servfails_instead_of_plain);
  RUN_TEST(test_forged_or_mismatched_replies_are_ignored);
  RUN_TEST(test_pipelines_queries_and_matches_out_of_order_replies);
  RUN_TEST(test_doh_sends_one_request_at_a_time);
  RUN_TEST(test_table_full_rejects_submit);
  RUN_TEST(test_closed_connection_reroutes_in_flight_queries);
  RUN_TEST(test_malformed_reply_counts_as_failure_and_reroutes);
  RUN_TEST(test_idle_connections_are_closed_before_the_server_does);
  RUN_TEST(test_reply_flood_cannot_trap_poll);
  RUN_TEST(test_slow_failing_connects_respect_the_blocking_budget);
  RUN_TEST(test_deadline_does_not_blame_an_upstream_that_had_no_time_to_answer);
  RUN_TEST(test_deadline_blames_an_upstream_that_had_time_to_answer);
  RUN_TEST(test_failed_doh_does_not_reconnect_for_each_queued_query);
  return UNITY_END();
}
