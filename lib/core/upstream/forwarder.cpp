#include "upstream/forwarder.h"

namespace upstream {

using hal::LogLevel;

namespace {
constexpr const char* kTag = "up";
}

Forwarder::Forwarder(const ForwarderConfig& cfg, ITransport* const* transports, size_t count,
                     const hal::IClock& clock, hal::IRandom& random, hal::ILogger& log,
                     IForwarderSink& sink)
    : cfg_(cfg),
      count_(count > kMaxUpstreams ? kMaxUpstreams : count),
      clock_(clock),
      random_(random),
      log_(log),
      sink_(sink) {
  for (size_t i = 0; i < count_; i++) {
    transports_[i] = transports[i];
    health_[i] = UpstreamHealth(cfg.health);
  }
}

size_t Forwarder::inFlight() const {
  size_t n = 0;
  for (const Slot& s : slots_) n += s.used ? 1 : 0;
  return n;
}

UpstreamStatus Forwarder::upstreamStatus(size_t i) const {
  UpstreamStatus st;
  if (i >= count_) return st;
  st.name = transports_[i]->name();
  st.kind = transports_[i]->kind();
  st.authenticated = transports_[i]->authenticated();
  st.connected = transports_[i]->connected();
  st.state = health_[i].state();
  st.stats = health_[i].stats();
  return st;
}

void Forwarder::recordSuccess(int u, uint32_t latencyMs) {
  const HealthState before = health_[u].state();
  health_[u].onSuccess(latencyMs);
  if (before != HealthState::kUp)
    log_.log(LogLevel::kInfo, kTag, "%s: %s -> up (%u ms)", transports_[u]->name(),
             healthStateName(before), static_cast<unsigned>(latencyMs));
  if (plainActive_ && transports_[u]->authenticated()) {
    plainActive_ = false;
    log_.log(LogLevel::kInfo, kTag, "encrypted upstream %s restored; plain DNS fallback off",
             transports_[u]->name());
  }
}

void Forwarder::recordFailure(int u) {
  const HealthState before = health_[u].state();
  health_[u].onFailure(clock_.monotonicMs(), random_.next32());
  const HealthState after = health_[u].state();
  if (after != before)
    log_.log(after == HealthState::kDown ? LogLevel::kWarn : LogLevel::kInfo, kTag,
             "%s: %s -> %s (retry in %u ms)", transports_[u]->name(), healthStateName(before),
             healthStateName(after), static_cast<unsigned>(health_[u].backoffMs()));
}

bool Forwarder::allEncryptedDown(uint64_t now) const {
  for (size_t i = 0; i < count_; i++)
    if (transports_[i]->authenticated() && health_[i].available(now)) return false;
  return true;
}

bool Forwarder::busy(int u) const {
  for (const Slot& s : slots_)
    if (s.used && !s.needsSend && s.upstream == u) return true;
  return false;
}

int Forwarder::selectUpstream(const Slot& s, uint64_t now) {
  for (size_t i = 0; i < count_; i++) {
    if ((s.tried >> i) & 1u) continue;
    if (transports_[i]->authenticated() && health_[i].available(now)) return static_cast<int>(i);
  }
  if (!cfg_.allowPlainFallback || !allEncryptedDown(now)) return -1;
  for (size_t i = 0; i < count_; i++) {
    if ((s.tried >> i) & 1u) continue;
    if (!transports_[i]->authenticated() && health_[i].available(now)) {
      if (!plainActive_) {
        plainActive_ = true;
        log_.log(LogLevel::kWarn, kTag,
                 "ALL encrypted upstreams down - using PLAIN DNS via %s (visible to ISP)",
                 transports_[i]->name());
      }
      return static_cast<int>(i);
    }
  }
  return -1;
}

uint16_t Forwarder::freshId(int u) {
  // With <= 32 slots a clash is rare; the bound only guards against a broken RNG.
  uint16_t id = random_.next16();
  for (int attempt = 0; attempt < 64; attempt++) {
    bool clash = false;
    for (const Slot& s : slots_)
      if (s.used && s.upstream == u && s.wireId == id && !s.needsSend) clash = true;
    if (!clash) break;
    id = random_.next16();
  }
  return id;
}

bool Forwarder::submit(uint32_t token, const dns::Query& q) {
  if (!q.hasQuestion) return false;
  callStartMs_ = clock_.monotonicMs();
  for (Slot& s : slots_) {
    if (s.used) continue;
    const uint64_t now = clock_.monotonicMs();
    s = Slot{};
    s.used = true;
    s.needsSend = true;
    s.token = token;
    s.q = q;
    s.arrivalMs = now;
    s.deadlineMs = now + cfg_.totalDeadlineMs;
    trySend(s);
    return true;
  }
  return false;
}

void Forwarder::finishFailed(Slot& s) {
  const uint32_t token = s.token;
  const dns::Query q = s.q;
  s.used = false;
  sink_.onFailure(token, q);
}

void Forwarder::reroute(Slot& s) {
  if (s.upstream >= 0) s.tried |= 1u << s.upstream;
  s.upstream = -1;
  s.needsSend = true;
}

void Forwarder::trySend(Slot& s) {
  while (s.used && s.needsSend) {
    const uint64_t now = clock_.monotonicMs();
    if (s.upstream < 0) {
      s.upstream = selectUpstream(s, now);
      if (s.upstream < 0) {
        // Nothing left to try: fail now unless an earlier upstream may still answer.
        finishFailed(s);
        return;
      }
      health_[s.upstream].beginProbe();
    }
    const int u = s.upstream;
    ITransport* t = transports_[u];
    if (!t->pipelined() && busy(u)) return;  // DoH: wait for the current request

    if (!t->connected()) {
      // A connect can block for connectTimeoutMs. Only start one if it still fits
      // the blocking budget of this call; otherwise retry on the next poll().
      if (clock_.monotonicMs() - callStartMs_ + cfg_.connectTimeoutMs > cfg_.maxBlockingMs) return;
      if (t->connect(cfg_.connectTimeoutMs) != IoStatus::kOk) {
        t->close();
        recordFailure(u);
        reroute(s);
        continue;
      }
    }
    s.wireId = freshId(u);
    const size_t n = dns::buildUpstreamQuery(s.q, s.wireId, cfg_.query, txBuf_, sizeof(txBuf_));
    if (n == 0) {
      finishFailed(s);
      return;
    }
    if (t->send(txBuf_, n) != IoStatus::kOk) {
      t->close();
      recordFailure(u);
      reroute(s);
      continue;
    }
    const uint64_t sent = clock_.monotonicMs();
    s.needsSend = false;
    s.sentMs = sent;
    s.hedgeAtMs = sent + cfg_.hedgeAfterMs;
    s.attempts++;
    lastActivityMs_[u] = sent;
  }
}

void Forwarder::failTransport(int u) {
  transports_[u]->close();
  recordFailure(u);
  for (Slot& s : slots_)
    if (s.used && !s.needsSend && s.upstream == u) reroute(s);
  for (Slot& s : slots_)
    if (s.used && s.needsSend) trySend(s);
}

void Forwarder::handleReply(int u, uint8_t* msg, size_t len) {
  if (len < dns::kHeaderSize) return;
  const uint16_t id = static_cast<uint16_t>((msg[0] << 8) | msg[1]);
  Slot* match = nullptr;
  for (Slot& s : slots_) {
    if (s.used && !s.needsSend && s.upstream == u && s.wireId == id &&
        dns::responseMatches(msg, len, id, s.q)) {
      match = &s;
      break;
    }
  }
  if (!match) {
    log_.log(LogLevel::kDebug, kTag, "%s: ignoring unmatched reply id %u", transports_[u]->name(), id);
    return;
  }
  lastActivityMs_[u] = clock_.monotonicMs();
  dns::ResponseInfo info;
  bool ok = dns::inspectResponse(msg, len, info);
  if (ok && info.hasOpt) {
    const size_t stripped = dns::stripTrailingOpt(msg, len, info);
    ok = stripped != 0 && dns::inspectResponse(msg, stripped, info);
    len = stripped;
  }
  if (!ok) {
    log_.log(LogLevel::kWarn, kTag, "%s: malformed reply, trying next upstream", transports_[u]->name());
    recordFailure(u);
    reroute(*match);
    trySend(*match);
    return;
  }
  recordSuccess(u, static_cast<uint32_t>(clock_.monotonicMs() - match->sentMs));
  const uint32_t token = match->token;
  const dns::Query q = match->q;
  match->used = false;
  sink_.onAnswer(token, q, msg, len, info, transports_[u]->authenticated());
}

void Forwarder::poll(uint32_t waitMs) {
  uint64_t now = clock_.monotonicMs();
  callStartMs_ = now;

  // 1. Close idle connections before the server does, so we never write into a
  //    half-closed socket.
  for (size_t i = 0; i < count_; i++) {
    ITransport* t = transports_[i];
    if (t->connected() && !busy(static_cast<int>(i)) && now - lastActivityMs_[i] >= cfg_.idleCloseMs)
      t->close();
  }

  // 2. Send anything waiting (new, rerouted, or queued behind a busy DoH).
  for (Slot& s : slots_)
    if (s.used && s.needsSend) trySend(s);

  // 3. Receive. Only the first receive call may block, and each transport yields at
  //    most kMaxRepliesPerPoll messages, so a flood of forged replies cannot keep
  //    this task busy forever.
  uint32_t wait = waitMs;
  for (size_t i = 0; i < count_; i++) {
    const int u = static_cast<int>(i);
    for (size_t budget = kMaxRepliesPerPoll; budget > 0 && busy(u); budget--) {
      size_t len = 0;
      const IoStatus st = transports_[i]->receive(rxBuf_, sizeof(rxBuf_), len, wait);
      wait = 0;
      if (st == IoStatus::kOk) {
        handleReply(u, rxBuf_, len);
        continue;
      }
      if (st == IoStatus::kClosed || st == IoStatus::kError) {
        log_.log(LogLevel::kInfo, kTag, "%s: connection %s with queries in flight",
                 transports_[i]->name(), st == IoStatus::kClosed ? "closed" : "failed");
        failTransport(u);
      }
      break;
    }
  }

  // 4. Hedge slow queries to the next upstream, and fail those past the deadline.
  now = clock_.monotonicMs();
  for (Slot& s : slots_) {
    if (!s.used) continue;
    if (now >= s.deadlineMs) {
      if (!s.needsSend && s.upstream >= 0) recordFailure(s.upstream);
      log_.log(LogLevel::kInfo, kTag, "timeout for %s, answering SERVFAIL", s.q.qname);
      finishFailed(s);
      continue;
    }
    if (!s.needsSend && now >= s.hedgeAtMs && s.attempts == 1) {
      Slot probe = s;
      probe.tried |= 1u << s.upstream;
      if (selectUpstream(probe, now) < 0) continue;  // nowhere better: keep waiting
      recordFailure(s.upstream);
      reroute(s);
      trySend(s);
    }
  }

  // 5. Replies may have freed a non-pipelined (DoH) connection: send what queued behind it.
  for (Slot& s : slots_)
    if (s.used && s.needsSend) trySend(s);
}

}  // namespace upstream
