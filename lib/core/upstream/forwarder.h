#pragma once
// Forwards cache-miss queries to an ordered chain of upstream transports.
//
//  - Encrypted upstreams (DoT/DoH) are tried in priority order, skipping Down ones.
//  - Plain UDP upstreams are used only when EVERY encrypted upstream is Down and plain
//    fallback is allowed; the switch is logged loudly once per transition.
//  - Each query gets a fresh random upstream ID and lives in a fixed in-flight table;
//    replies must match ID and question (late or forged replies are ignored).
//  - A query unanswered after hedgeAfterMs is re-sent to the next healthy upstream;
//    at totalDeadlineMs the client gets SERVFAIL via the sink.
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
  uint32_t connectTimeoutMs = 3000;
  // Upper bound on blocking connects per submit()/poll() call: keeps the upstream
  // task well inside the 5 s task watchdog when every upstream is unreachable.
  uint32_t maxBlockingMs = 4000;
  uint32_t idleCloseMs = 9000;       // servers drop idle DoT after ~10 s
  bool allowPlainFallback = true;
  dns::UpstreamQueryOptions query;   // padding, AD request
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

struct UpstreamStatus {
  const char* name = "";
  TransportKind kind = TransportKind::kUdp;
  bool authenticated = false;
  bool connected = false;
  HealthState state = HealthState::kUnknown;
  HealthStats stats;
};

class Forwarder {
 public:
  static constexpr size_t kMaxInFlight = 32;
  static constexpr size_t kMaxUpstreams = 8;
  static constexpr size_t kMaxAnswer = 4096;
  static constexpr size_t kMaxRepliesPerPoll = 64;

  Forwarder(const ForwarderConfig& cfg, ITransport* const* transports, size_t count,
            const hal::IClock& clock, hal::IRandom& random, hal::ILogger& log, IForwarderSink& sink);
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
  };

  int selectUpstream(const Slot& s, uint64_t now);
  bool allEncryptedDown(uint64_t now) const;
  bool busy(int u) const;
  void trySend(Slot& s);
  void handleReply(int u, uint8_t* msg, size_t len);
  void failTransport(int u);
  void reroute(Slot& s);
  void finishFailed(Slot& s);
  void recordSuccess(int u, uint32_t latencyMs);
  void recordFailure(int u);
  uint16_t freshId(int u);

  ForwarderConfig cfg_;
  ITransport* transports_[kMaxUpstreams] = {};
  UpstreamHealth health_[kMaxUpstreams];
  uint64_t lastActivityMs_[kMaxUpstreams] = {};
  size_t count_;
  const hal::IClock& clock_;
  hal::IRandom& random_;
  hal::ILogger& log_;
  IForwarderSink& sink_;
  Slot slots_[kMaxInFlight];
  bool plainActive_ = false;
  uint64_t callStartMs_ = 0;
  uint8_t txBuf_[512];
  uint8_t rxBuf_[kMaxAnswer];
};

}  // namespace upstream
