#include "upstream/forwarder.h"

namespace upstream {

using hal::LogLevel;

namespace {
constexpr const char* kTag = "up";
}

const char* probeResultName(ProbeResult r) {
  switch (r) {
    case ProbeResult::kNone: return "none";
    case ProbeResult::kPending: return "pending";
    case ProbeResult::kOk: return "ok";
    case ProbeResult::kConnectFailed: return "connect failed";
    case ProbeResult::kSendFailed: return "send failed";
    case ProbeResult::kClosed: return "connection closed";
    case ProbeResult::kTimeout: return "timeout";
    case ProbeResult::kBadReply: return "bad reply";
  }
  return "?";
}

Forwarder::Forwarder(const ForwarderConfig& cfg, ITransport* const* transports, size_t count,
                     const hal::IClock& clock, hal::IRandom& random, hal::ILogger& log, IForwarderSink& sink)
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
  st.backoffMs = health_[i].backoffMs();
  st.stats = health_[i].stats();
  st.probe = probe_[i];
  return st;
}

void Forwarder::recordSuccess(int u, uint32_t latencyMs) {
  const HealthState before = health_[u].state();
  health_[u].onSuccess(latencyMs);
  if (before != HealthState::kUp)
    log_.log(LogLevel::kInfo, kTag, "%s: %s -> up (%u ms)", transports_[u]->name(), healthStateName(before),
             static_cast<unsigned>(latencyMs));
  if (outage_) {
    // First answer after every upstream was down: the failures were most likely our own
    // connection, so don't leave the others "down" on stale evidence.
    outage_ = false;
    for (size_t i = 0; i < count_; i++)
      if (static_cast<int>(i) != u && health_[i].state() != HealthState::kUp) health_[i].reset();
    log_.log(LogLevel::kInfo, kTag, "connectivity restored via %s: other upstreams back to unknown",
             transports_[u]->name());
  }
  if (plainActive_ && transports_[u]->authenticated()) {
    plainActive_ = false;
    // Plain upstreams are only used during fallback: whatever state they were left in
    // ("up" or "down") would otherwise be shown forever. Not in use: "unknown".
    for (size_t i = 0; i < count_; i++)
      if (!transports_[i]->authenticated()) health_[i].reset();
    log_.log(LogLevel::kInfo, kTag, "encrypted upstream %s restored; plain DNS fallback off",
             transports_[u]->name());
  }
}

void Forwarder::recordFailure(int u) {
  // A plain upstream is only judged while plain fallback is in use: outside it, a failure
  // is a leftover (e.g. a query from an outage timing out after recovery).
  if (!transports_[u]->authenticated() && !plainActive_) return;
  const uint64_t now = clock_.monotonicMs();
  const HealthState before = health_[u].state();
  health_[u].onFailure(now, random_.next32());
  const bool everythingDown = allDown();
  // Cap first, so the log below shows the real retry delay. Every upstream down: our
  // own internet is the likely cause. Every encrypted one down while plain DNS still
  // works: queries go out in plaintext, so get back to encrypted DNS quickly.
  const bool encryptedDown = !everythingDown && encryptedAllFailing();
  if (everythingDown || encryptedDown)
    for (size_t i = 0; i < count_; i++)
      if (everythingDown || transports_[i]->authenticated()) health_[i].capBackoff(now, cfg_.outageProbeMs);
  const HealthState after = health_[u].state();
  if (after != before)
    log_.log(after == HealthState::kDown ? LogLevel::kWarn : LogLevel::kInfo, kTag,
             "%s: %s -> %s (retry in %u ms)", transports_[u]->name(), healthStateName(before),
             healthStateName(after), static_cast<unsigned>(health_[u].backoffMs()));
  if (everythingDown && !outage_) {
    outage_ = true;
    log_.log(LogLevel::kWarn, kTag,
             "every upstream is failing: internet connection down? retrying every %u s",
             static_cast<unsigned>(cfg_.outageProbeMs / 1000));
  }
}

void Forwarder::blameSilence(int u, uint64_t sentMs, uint64_t now) {
  if (lastReplyMs_[u] > sentMs || now < nextBlameMs_[u]) return;
  nextBlameMs_[u] = now + cfg_.hedgeAfterMs;
  recordFailure(u);
}

bool Forwarder::encryptedAllFailing() const {
  bool any = false;
  for (size_t i = 0; i < count_; i++) {
    if (!transports_[i]->authenticated()) continue;
    any = true;
    const HealthState st = health_[i].state();
    if (st != HealthState::kDown && st != HealthState::kProbing) return false;
  }
  return any;
}

bool Forwarder::allDown() const {
  for (size_t i = 0; i < count_; i++) {
    const HealthState st = health_[i].state();
    if (st != HealthState::kDown && st != HealthState::kProbing) return false;
  }
  return count_ > 0;
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

bool Forwarder::roomToConnect(int u, bool makeRoom) {
  if (transports_[u]->connected() || transports_[u]->kind() == TransportKind::kUdp) return true;
  uint32_t open = 0;
  int idlest = -1;
  for (size_t i = 0; i < count_; i++) {
    const int v = static_cast<int>(i);
    if (transports_[i]->kind() == TransportKind::kUdp || !transports_[i]->connected()) continue;
    open++;
    if (!busy(v) && (idlest < 0 || lastActivityMs_[i] < lastActivityMs_[idlest])) idlest = v;
  }
  if (open < cfg_.maxTlsConnections) return true;
  if (idlest < 0) return false;  // every connection has queries in flight: wait
  if (makeRoom) transports_[idlest]->close();
  return true;
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
  for (size_t i = 0; i < kMaxInFlight; i++) {  // the last slot is the probe's
    Slot& s = slots_[i];
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
      if (!roomToConnect(u, true)) return;  // at the TLS limit: retry on the next poll()
      if (t->connect(cfg_.connectTimeoutMs) != IoStatus::kOk) {
        if (s.probe) {
          const int32_t err = t->lastError();
          t->close();
          finishProbe(s, ProbeResult::kConnectFailed, err);
          return;
        }
        // TCP failures (no route, blackhole) are routine during an outage; a TLS-stage
        // error (e.g. -0x7F00 out of memory, a bad certificate) is worth seeing.
        if (t->lastError() != 0)
          log_.log(LogLevel::kWarn, kTag, "%s: TLS connect failed (error -0x%04x)", t->name(),
                   static_cast<unsigned>(-t->lastError()));
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
      if (s.probe) {
        finishProbe(s, ProbeResult::kSendFailed);
        return;
      }
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
  // A probe alone on the connection doesn't count against its health.
  bool clientQueries = false;
  for (const Slot& s : slots_)
    if (s.used && s.upstream == u && !s.probe) clientQueries = true;
  if (clientQueries) recordFailure(u);
  // Reroute everything assigned to it, including queries queued behind a busy DoH
  // connection (needsSend with upstream == u): left alone, each would reconnect to the
  // failed server on its own.
  for (Slot& s : slots_) {
    if (!s.used || s.upstream != u) continue;
    if (s.probe)
      finishProbe(s, ProbeResult::kClosed);
    else
      reroute(s);
  }
  for (Slot& s : slots_)
    if (s.used && s.needsSend) trySend(s);
}

void Forwarder::handleReply(int u, uint8_t* msg, size_t len) {
  if (len < dns::kHeaderSize) return;
  lastReplyMs_[u] = clock_.monotonicMs();
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
  if (match->probe) {
    const uint32_t latency = static_cast<uint32_t>(clock_.monotonicMs() - match->sentMs);
    if (!ok) {
      finishProbe(*match, ProbeResult::kBadReply);
      return;
    }
    // It works: a stale Down/Degraded goes back to Unknown (standby), so it is usable
    // again and the dashboard folds it away with the other standbys. A test isn't
    // traffic: OK count, latency and an Up state are left alone. Plain upstreams keep
    // their state (only judged while plain fallback is in use).
    const HealthState before = health_[u].state();
    if (transports_[u]->authenticated() && before != HealthState::kUp && before != HealthState::kUnknown) {
      health_[u].reset();
      log_.log(LogLevel::kInfo, kTag, "%s: %s -> unknown (test passed)", transports_[u]->name(),
               healthStateName(before));
    }
    finishProbe(*match, ProbeResult::kOk, 0, latency, static_cast<uint8_t>(info.rcode));
    return;
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

void Forwarder::handleTooBig(int u, const uint8_t* msg, size_t len) {
  // The upstream answered (so it is alive), but the answer exceeds kMaxAnswer: no other
  // upstream will do better, so that one client gets SERVFAIL now instead of at the
  // deadline, and nobody is blamed (audit 2026-11).
  lastReplyMs_[u] = clock_.monotonicMs();
  lastActivityMs_[u] = lastReplyMs_[u];
  const bool haveId = len >= 2;
  const uint16_t id = haveId ? static_cast<uint16_t>((msg[0] << 8) | msg[1]) : 0;
  for (Slot& s : slots_) {
    if (!s.used || s.needsSend || s.upstream != u) continue;
    if (haveId ? s.wireId != id : transports_[u]->pipelined()) continue;  // no ID: only one in flight
    log_.log(LogLevel::kInfo, kTag, "%s: answer for %s larger than %u bytes, answering SERVFAIL",
             transports_[u]->name(), s.q.qname, static_cast<unsigned>(kMaxAnswer));
    if (s.probe)
      finishProbe(s, ProbeResult::kBadReply);
    else
      finishFailed(s);
    return;
  }
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
  driveProbe();
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
      if (st == IoStatus::kTooBig) {
        handleTooBig(u, rxBuf_, len);
        continue;
      }
      if (st == IoStatus::kClosed || st == IoStatus::kError) {
        log_.log(LogLevel::kInfo, kTag, "%s: connection %s with queries in flight", transports_[i]->name(),
                 st == IoStatus::kClosed ? "closed" : "failed");
        failTransport(u);
      }
      break;
    }
  }

  // 4. Hedge slow queries to the next upstream, and fail those past the deadline.
  now = clock_.monotonicMs();
  for (Slot& s : slots_) {
    if (!s.used) continue;
    if (s.probe) {
      if (now >= s.deadlineMs) finishProbe(s, ProbeResult::kTimeout);
      continue;  // never hedged
    }
    if (now >= s.deadlineMs) {
      // Blame the upstream only if it had a fair chance (hedgeAfterMs since this send).
      // A query that reached it late, e.g. after a blackholed upstream used up the
      // budget in its connect timeout, says nothing about its health.
      if (!s.needsSend && s.upstream >= 0 && now - s.sentMs >= cfg_.hedgeAfterMs)
        blameSilence(s.upstream, s.sentMs, now);
      log_.log(LogLevel::kInfo, kTag, "timeout for %s, answering SERVFAIL", s.q.qname);
      finishFailed(s);
      continue;
    }
    if (!s.needsSend && now >= s.hedgeAtMs && s.attempts == 1) {
      Slot probe = s;
      probe.tried |= 1u << s.upstream;
      const int next = selectUpstream(probe, now);
      if (next < 0 || !roomToConnect(next, false)) continue;  // nowhere better: keep waiting
      // Only blame an upstream that has gone silent. One that answered anything since
      // this query was sent is alive, just slow (e.g. a congested link right after the
      // internet comes back); marking it down would push every query onto the next one.
      blameSilence(s.upstream, s.sentMs, now);
      reroute(s);
      trySend(s);
    }
  }

  // 5. Replies may have freed a non-pipelined (DoH) connection: send what queued behind it.
  for (Slot& s : slots_)
    if (s.used && s.needsSend) trySend(s);
}

bool Forwarder::startProbe(const dns::Query& q) {
  if (probeActive_ || !q.hasQuestion) return false;
  for (size_t i = 0; i < count_; i++) probe_[i] = ProbeStatus{ProbeResult::kPending, 0, 0, 0};
  probeQ_ = q;
  probeNext_ = 0;
  probeActive_ = true;
  log_.log(LogLevel::kInfo, kTag, "testing %u upstreams", static_cast<unsigned>(count_));
  return true;
}

void Forwarder::driveProbe() {
  if (!probeActive_) return;
  Slot& s = slots_[kMaxInFlight];
  if (s.used) return;          // one at a time
  if (probeNext_ >= count_) {  // only with an empty chain; finishProbe() ends a run
    probeActive_ = false;
    return;
  }
  const uint64_t now = clock_.monotonicMs();
  s = Slot{};
  s.used = true;
  s.needsSend = true;
  s.probe = true;
  s.q = probeQ_;
  s.upstream = static_cast<int>(probeNext_++);
  s.arrivalMs = now;
  s.deadlineMs = now + cfg_.probeTimeoutMs;
}

void Forwarder::finishProbe(Slot& s, ProbeResult r, int32_t tlsError, uint32_t latencyMs, uint8_t rcode) {
  const int u = s.upstream;
  s.used = false;
  probe_[u] = ProbeStatus{r, latencyMs, rcode, tlsError};
  if (probeNext_ >= count_) probeActive_ = false;  // that was the last one
  if (r == ProbeResult::kOk)
    log_.log(LogLevel::kInfo, kTag, "test %s: ok (%u ms, rcode %u)", transports_[u]->name(),
             static_cast<unsigned>(latencyMs), static_cast<unsigned>(rcode));
  else if (tlsError != 0)
    log_.log(LogLevel::kWarn, kTag, "test %s: %s (TLS error -0x%04x)", transports_[u]->name(),
             probeResultName(r), static_cast<unsigned>(-tlsError));
  else
    log_.log(LogLevel::kWarn, kTag, "test %s: %s", transports_[u]->name(), probeResultName(r));
}

}  // namespace upstream
