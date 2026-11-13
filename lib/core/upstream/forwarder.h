#pragma once
// Forwards cache-miss queries to an ordered chain of upstream transports.
//
//  - Encrypted upstreams (DoT/DoH) are tried in priority order, skipping Down ones.
//  - Plain UDP upstreams are used only when EVERY encrypted upstream is Down and plain
//    fallback is allowed; the switch is logged loudly once per transition.
//  - Each query gets a fresh random upstream ID and lives in a fixed in-flight table;
//    replies must match ID and question (late or forged replies are ignored).
//  - A query unanswered after hedgeAfterMs is re-sent to the next healthy upstream;
//    at totalDeadlineMs the client gets SERVFAIL via the sink. Silence counts against
//    an upstream at most once per hedgeAfterMs, and never if it answered anything since
//    the query was sent: a burst of queries stuck on a slow authoritative server must
//    not take encrypted DNS down (and push the LAN onto plain DNS).
//  - While every encrypted upstream is down, they are retried at least every
//    outageProbeMs, so plain fallback ends soon after one comes back.
//  - At most maxTlsConnections DoT/DoH connections are open at once: a new one first
//    closes the longest-idle one, or waits until one is idle.
//  - startProbe() tests every upstream in turn with one query each (dashboard "Test
//    upstreams"): standby upstreams are otherwise only used when the active one fails,
//    so their state can be hours old.
//
// Driven by the upstream task: submit() new queries, call poll() in a loop.
// Not thread-safe; owned by one task.

#include <cstddef>
#include <cstdint>

#include "dns/message.h"
#include "hal/clock.h"
#include "hal/logger.h"
#include "hal/random.h"
#include "upstream/health.h"
#include "upstream/transport.h"

namespace upstream {

struct ForwarderConfig {
  uint32_t totalDeadlineMs = 2500;
  uint32_t hedgeAfterMs = 1200;
  // TCP connect + TLS handshake. A full handshake measured ~1.5 s on the ESP32-S3
  // (2026-10-15), so this stays at 3 s; the TCP stage alone is capped much lower in
  // platform::TlsStream, so a blackholed upstream fails fast.
  uint32_t connectTimeoutMs = 3000;
  // Upper bound on blocking connects per submit()/poll() call: keeps the upstream
  // task well inside the 5 s task watchdog when every upstream is unreachable.
  uint32_t maxBlockingMs = 4000;
  uint32_t idleCloseMs = 9000;  // servers drop idle DoT after ~10 s
  // When every upstream is Down at once the local internet connection is the likely
  // cause (ISP outage), not the providers: probe at least this often so lookups recover
  // within seconds of it coming back, instead of after a backoff of up to 5 min.
  uint32_t outageProbeMs = 10000;
  // Each TLS session takes ~45 KB of internal RAM (mbedTLS can't use PSRAM here).
  // Found on hardware: after a power cut the slow, just-restored internet made every
  // query hedge, a connection opened to each upstream in turn, and internal RAM ran
  // out (failed handshakes, dropped packets) until a reboot. ARCHITECTURE.md §11.
  uint32_t maxTlsConnections = 2;
  bool allowPlainFallback = true;
  // One upstream test query: connect (connectTimeoutMs) plus the reply.
  uint32_t probeTimeoutMs = 5000;
  dns::UpstreamQueryOptions query;  // padding, AD request
  HealthConfig health;
};

class IForwarderSink {
 public:
  virtual ~IForwarderSink() = default;
  // A validated answer for `q` with its OPT removed; `info` describes it. The buffer
  // is only valid during the call.
  virtual void onAnswer(uint32_t token, const dns::Query& q, const uint8_t* answer, size_t len,
                        const dns::ResponseInfo& info, bool authenticated) = 0;
  // No upstream could answer in time: reply SERVFAIL.
  virtual void onFailure(uint32_t token, const dns::Query& q) = 0;
};

// Result of the last startProbe() run for one upstream.
enum class ProbeResult : uint8_t {
  kNone,           // never tested
  kPending,        // waiting for its turn, or in flight
  kOk,             // a valid reply (any RCODE)
  kConnectFailed,  // TCP connect or TLS handshake failed (see tlsError)
  kSendFailed,
  kClosed,    // connection closed or failed before the reply
  kTimeout,   // no reply within probeTimeoutMs
  kBadReply,  // malformed reply
};

const char* probeResultName(ProbeResult r);

struct ProbeStatus {
  ProbeResult result = ProbeResult::kNone;
  uint32_t latencyMs = 0;  // query sent -> reply (kOk only)
  uint8_t rcode = 0;       // kOk only
  int32_t tlsError = 0;    // kConnectFailed: mbedTLS error, 0 = failed before TLS (TCP)
};

struct UpstreamStatus {
  const char* name = "";
  TransportKind kind = TransportKind::kUdp;
  bool authenticated = false;
  bool connected = false;
  HealthState state = HealthState::kUnknown;
  uint32_t backoffMs = 0;  // current retry delay while Down
  HealthStats stats;
  ProbeStatus probe;
};

class Forwarder {
 public:
  static constexpr size_t kMaxInFlight = 32;
  static constexpr size_t kMaxUpstreams = 8;
  static constexpr size_t kMaxAnswer = 4096;
  static constexpr size_t kMaxRepliesPerPoll = 64;

  Forwarder(const ForwarderConfig& cfg, ITransport* const* transports, size_t count, const hal::IClock& clock,
            hal::IRandom& random, hal::ILogger& log, IForwarderSink& sink);
  Forwarder(const Forwarder&) = delete;
  Forwarder& operator=(const Forwarder&) = delete;

  // Queues a validated cache-miss query. False if the in-flight table is full
  // (caller should answer SERVFAIL). May call the sink synchronously.
  bool submit(uint32_t token, const dns::Query& q);

  // Sends pending queries, receives replies (blocking at most waitMs once), and
  // enforces hedging/deadlines.
  void poll(uint32_t waitMs);

  size_t inFlight() const;
  bool plainFallbackActive() const { return plainActive_; }
  void setAllowPlainFallback(bool allow) { cfg_.allowPlainFallback = allow; }
  size_t upstreamCount() const { return count_; }
  UpstreamStatus upstreamStatus(size_t i) const;

  // Tests every upstream in chain order with one query each (`q`), one at a time,
  // alongside normal traffic and within maxTlsConnections. Sent even to Down upstreams
  // and to plain ones whatever the fallback setting; never rerouted or hedged, and the
  // sink never sees it. A success puts a Down/Degraded encrypted upstream back to
  // Unknown (standby); nothing else changes health state or counters, the result is
  // only reported in upstreamStatus(i).probe. False if a test is already running.
  bool startProbe(const dns::Query& q);
  bool probing() const { return probeActive_; }

 private:
  struct Slot {
    bool used = false;
    bool needsSend = false;
    uint32_t token = 0;
    dns::Query q;
    int upstream = -1;
    uint16_t wireId = 0;
    uint64_t arrivalMs = 0;
    uint64_t sentMs = 0;
    uint64_t deadlineMs = 0;
    uint64_t hedgeAtMs = 0;
    uint8_t attempts = 0;
    uint32_t tried = 0;  // bitmask of upstreams already used
    bool probe = false;  // a startProbe() query: pinned to `upstream`, no sink
  };

  int selectUpstream(const Slot& s, uint64_t now);
  bool allEncryptedDown(uint64_t now) const;
  bool allDown() const;  // every upstream Down or Probing
  bool busy(int u) const;
  // True if `u` is connected, isn't TLS, or a TLS connection may be opened for it
  // (under the limit, or an idle one can be closed; closed now if `makeRoom`).
  bool roomToConnect(int u, bool makeRoom);
  void trySend(Slot& s);
  void handleReply(int u, uint8_t* msg, size_t len);
  void failTransport(int u);
  void reroute(Slot& s);
  void finishFailed(Slot& s);
  void recordSuccess(int u, uint32_t latencyMs);
  void recordFailure(int u);
  // Blames `u` for a query sent at sentMs that is still unanswered, unless it answered
  // anything since then or was already blamed in the last hedgeAfterMs.
  void blameSilence(int u, uint64_t sentMs, uint64_t now);
  bool encryptedAllFailing() const;  // every encrypted upstream Down or Probing
  uint16_t freshId(int u);
  void driveProbe();
  void finishProbe(Slot& s, ProbeResult r, int32_t tlsError = 0, uint32_t latencyMs = 0, uint8_t rcode = 0);

  ForwarderConfig cfg_;
  ITransport* transports_[kMaxUpstreams] = {};
  UpstreamHealth health_[kMaxUpstreams];
  uint64_t lastActivityMs_[kMaxUpstreams] = {};
  uint64_t lastReplyMs_[kMaxUpstreams] = {};  // any reply, matched or late: it's alive
  uint64_t nextBlameMs_[kMaxUpstreams] = {};  // blameSilence() window
  size_t count_;
  const hal::IClock& clock_;
  hal::IRandom& random_;
  hal::ILogger& log_;
  IForwarderSink& sink_;
  Slot slots_[kMaxInFlight + 1];  // +1: a probe never takes a client's slot
  bool plainActive_ = false;
  bool outage_ = false;  // every upstream went down at once (see outageProbeMs)
  uint64_t callStartMs_ = 0;
  bool probeActive_ = false;
  size_t probeNext_ = 0;
  dns::Query probeQ_;
  ProbeStatus probe_[kMaxUpstreams];
  uint8_t txBuf_[512];
  uint8_t rxBuf_[kMaxAnswer];
};

}  // namespace upstream
