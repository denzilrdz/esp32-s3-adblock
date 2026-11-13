#include "tasks/dns_service.h"

#include <esp_task_wdt.h>

#include <cstring>
#include <new>

#include "util/bytes.h"
#include "util/net.h"
#include "util/send_deadline.h"

namespace app {

using hal::LogLevel;

namespace {

constexpr const char* kTag = "dns";
constexpr int kIoPriority = 10;
constexpr int kUpstreamPriority = 8;
constexpr int kTcpPriority = 5;
constexpr uint32_t kIoStack = 6144;
constexpr uint32_t kTcpStack = 6144;
constexpr uint32_t kUpstreamStack = 12288;  // TLS handshake needs headroom
constexpr int kDnsCore = 1;
constexpr int kTcpCore = 0;
// After a full batch dns_io yields for one tick: under a steady flood it never
// blocked in select(), so dns_up (prio 8) and everything below it on core 1 starved
// until a watchdog reset the board (audit 2026-11).
constexpr int kMaxDatagramsPerWake = 16;
// TCP abuse limits (one LAN client must not be able to starve everyone else):
constexpr uint32_t kTcpWriteTimeoutMs = 500;   // per send(): a client that doesn't read is dropped
constexpr uint32_t kTcpWriteBudgetMs = 1000;   // per reply: one that reads a trickle is too
constexpr uint32_t kTcpPartialFrameMs = 2000;  // slow-loris: a frame must arrive quickly
constexpr uint8_t kTcpMaxInFlightPerConn = 4;  // pipelined queries awaiting upstream
constexpr uint8_t kTcpMaxInFlightTotal = 8;    // share of the pending pool for all TCP
// Looked up through each upstream by startUpstreamTest(): reserved by RFC 2606, so it
// always resolves and is never on a blocklist.
constexpr const char* kUpstreamTestName = "example.com";

// Only answer the LAN (util::isPrivateIpv4): never an open resolver.
bool isPrivateSource(const struct sockaddr_in& a) {
  return util::isPrivateIpv4(ntohl(a.sin_addr.s_addr));
}

void drainSocket(int fd) {
  uint8_t drain[16];
  while (recv(fd, drain, sizeof(drain), MSG_DONTWAIT) > 0) {
  }
}

}  // namespace

DnsService::DnsService(const DnsServiceConfig& cfg, dns::IQueryPolicy& policy, const hal::IClock& clock,
                       hal::IRandom& random, hal::ILogger& log, upstream::ITransport* const* transports,
                       size_t transportCount)
    : cfg_(cfg),
      policy_(policy),
      clock_(clock),
      random_(random),
      log_(log),
      transports_(transports),
      transportCount_(transportCount) {
  if (cfg_.pendingSlots > upstream::Forwarder::kMaxInFlight)
    cfg_.pendingSlots = upstream::Forwarder::kMaxInFlight;
  udpInFlight_ =
      clients::InFlightLimiter(cfg_.pendingPerClient ? cfg_.pendingPerClient : cfg_.pendingSlots / 2,
                               static_cast<uint16_t>(cfg_.pendingSlots / 4));  // reserve for others
  if (cfg_.tcpMaxConns > sizeof(tcp_) / sizeof(tcp_[0])) cfg_.tcpMaxConns = sizeof(tcp_) / sizeof(tcp_[0]);
  if (cfg_.replyCap < dns::kMaxUdpPayload) cfg_.replyCap = dns::kMaxUdpPayload;
  if (cfg_.replyCap > upstream::Forwarder::kMaxAnswer) cfg_.replyCap = upstream::Forwarder::kMaxAnswer;
  memset(&udpWakeAddr_, 0, sizeof(udpWakeAddr_));
  memset(&tcpWakeAddr_, 0, sizeof(tcpWakeAddr_));
}

bool DnsService::createWakePair(int& rxFd, struct sockaddr_in& addr) {
  rxFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;  // ephemeral
  socklen_t len = sizeof(addr);
  return rxFd >= 0 && bind(rxFd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0 &&
         getsockname(rxFd, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0;
}

bool DnsService::start() {
  // Large, long-lived allocations happen once here (PSRAM when available).
  cacheMemory_ = platform::makeLargeBuffer(cache::ResponseCache::requiredBytes(cfg_.cache));
  poolMemory_ = platform::makeLargeBuffer(sizeof(Pending) * cfg_.pendingSlots);
  replyMemory_ = platform::makeLargeBuffer(cfg_.replyCap * cfg_.pendingSlots);
  void* fwdMemory = platform::allocLarge(sizeof(upstream::Forwarder));
  void* cacheObj = platform::allocLarge(sizeof(cache::ResponseCache));
  if (!cacheMemory_ || !poolMemory_ || !replyMemory_ || !fwdMemory || !cacheObj) {
    log_.log(LogLevel::kError, kTag, "out of memory for cache/pool");
    return false;
  }
  cache_ = new (cacheObj) cache::ResponseCache(cfg_.cache, cacheMemory_.get(), clock_);
  forwarder_ = new (fwdMemory)
      upstream::Forwarder(cfg_.forwarder, transports_, transportCount_, clock_, random_, log_, *this);
  pool_ = reinterpret_cast<Pending*>(poolMemory_.get());
  for (uint16_t i = 0; i < cfg_.pendingSlots; i++) {
    new (&pool_[i]) Pending();
    pool_[i].reply = replyMemory_.get() + cfg_.replyCap * i;
  }

  freeQ_ = xQueueCreate(cfg_.pendingSlots, sizeof(uint16_t));
  upQ_ = xQueueCreate(cfg_.pendingSlots, sizeof(uint16_t));
  udpReplyQ_ = xQueueCreate(cfg_.pendingSlots, sizeof(uint16_t));
  tcpReplyQ_ = xQueueCreate(cfg_.pendingSlots, sizeof(uint16_t));
  if (!freeQ_ || !upQ_ || !udpReplyQ_ || !tcpReplyQ_) return false;
  for (uint16_t i = 0; i < cfg_.pendingSlots; i++) xQueueSend(freeQ_, &i, 0);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg_.port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  udpFd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (udpFd_ < 0 || bind(udpFd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
    log_.log(LogLevel::kError, kTag, "cannot bind UDP port %u", cfg_.port);
    return false;
  }
  wakeTxFd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (wakeTxFd_ < 0 || !createWakePair(udpWakeRxFd_, udpWakeAddr_)) {
    log_.log(LogLevel::kError, kTag, "cannot create wake socket");
    return false;
  }
  if (cfg_.tcpEnabled) {
    // Backlog 1: every queued connection holds an lwIP netconn (16 in all, §11).
    tcpListenFd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int one = 1;
    setsockopt(tcpListenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (tcpListenFd_ < 0 ||
        bind(tcpListenFd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0 ||
        listen(tcpListenFd_, 1) != 0 || !createWakePair(tcpWakeRxFd_, tcpWakeAddr_)) {
      log_.log(LogLevel::kWarn, kTag, "TCP/53 unavailable; UDP only");
      if (tcpListenFd_ >= 0) close(tcpListenFd_);
      tcpListenFd_ = -1;
      cfg_.tcpEnabled = false;
    }
  }

  if (xTaskCreatePinnedToCore(ioTaskEntry, "dns_io", kIoStack, this, kIoPriority, nullptr, kDnsCore) !=
          pdPASS ||
      xTaskCreatePinnedToCore(upstreamTaskEntry, "dns_up", kUpstreamStack, this, kUpstreamPriority, nullptr,
                              kDnsCore) != pdPASS ||
      (cfg_.tcpEnabled && xTaskCreatePinnedToCore(tcpTaskEntry, "dns_tcp", kTcpStack, this, kTcpPriority,
                                                  nullptr, kTcpCore) != pdPASS)) {
    log_.log(LogLevel::kError, kTag, "cannot start DNS tasks");
    return false;
  }
  running_ = true;
  log_.log(LogLevel::kInfo, kTag, "listening on UDP%s %u (%u upstreams, %u-entry cache)",
           cfg_.tcpEnabled ? "+TCP" : "", cfg_.port, static_cast<unsigned>(transportCount_),
           static_cast<unsigned>(cfg_.cache.maxEntries));
  return true;
}

void DnsService::ioTaskEntry(void* self) {
  static_cast<DnsService*>(self)->ioLoop();
}
void DnsService::tcpTaskEntry(void* self) {
  static_cast<DnsService*>(self)->tcpLoop();
}
void DnsService::upstreamTaskEntry(void* self) {
  static_cast<DnsService*>(self)->upstreamLoop();
}

// --------------------------------------------------------------------------------
// Shared pipeline (dns_io and dns_tcp)

size_t DnsService::processQuery(const uint8_t* pkt, size_t len, const ClientRef& client, Work& work,
                                uint8_t* out, size_t outCap, bool* forwarded) {
  if (forwarded) *forwarded = false;
  stats_.queries++;
  if (client.origin == Origin::kTcp) stats_.tcpQueries++;
  if (!isPrivateSource(client.addr)) {
    stats_.dropped++;
    return 0;
  }
  dns::Query q;
  const dns::ParseStatus st = dns::parseQuery(pkt, len, q);
  dns::Rcode errorRcode = dns::Rcode::kNoError;
  switch (st) {
    case dns::ParseStatus::kOk: break;
    case dns::ParseStatus::kDrop: stats_.dropped++; return 0;
    case dns::ParseStatus::kFormErr: errorRcode = dns::Rcode::kFormErr; break;
    case dns::ParseStatus::kNotImp: errorRcode = dns::Rcode::kNotImp; break;
    case dns::ParseStatus::kRefused: errorRcode = dns::Rcode::kRefused; break;
    case dns::ParseStatus::kBadVers: errorRcode = dns::Rcode::kBadVers; break;
  }
  if (st == dns::ParseStatus::kOk && q.qtype == dns::kTypeAny) errorRcode = dns::Rcode::kNotImp;
  if (errorRcode != dns::Rcode::kNoError) {
    stats_.errors++;
    return dns::buildErrorReply(q, errorRcode, out, outCap);
  }

  // Local names never leave the device.
  switch (dns::classifyLocal(q.qname, q.qnameLen, cfg_.local)) {
    case dns::LocalAnswer::kLocalhost: {
      static const uint8_t v4[4] = {127, 0, 0, 1};
      static const uint8_t v6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
      stats_.local++;
      return dns::buildAddressReply(q, v4, v6, cfg_.localTtl, out, outCap);
    }
    case dns::LocalAnswer::kNxDomain:
      stats_.local++;
      return dns::buildNegativeReply(q, dns::Rcode::kNxDomain, cfg_.localTtl, out, outCap);
    case dns::LocalAnswer::kNone: break;
  }

  const dns::PolicyAction action = policy_.decide(q, client.addr.sin_addr.s_addr, work.rewrite);
  if (action == dns::PolicyAction::kRewrite) return processRewrite(q, client, work, out, outCap, forwarded);
  if (action != dns::PolicyAction::kForward) {
    dns::BlockedReplyOptions opt;
    opt.ttl = cfg_.blockedTtl;
    opt.ede = action == dns::PolicyAction::kBan ? dns::kEdeFiltered : dns::kEdeBlocked;
    stats_.blocked++;
    return dns::buildBlockedReply(q, opt, out, outCap);
  }

  // Cache hit: only answers from authenticated upstreams are cached, so AD may pass.
  size_t n;
  {
    platform::LockGuard g(cacheMutex_);
    n = cache_->lookup(q, work.scratch, work.scratchCap);
  }
  if (n) {
    dns::ClientReplyOptions co;
    co.authenticatedUpstream = cfg_.passAd;  // only authenticated answers are cached
    co.sizeLimit = sizeLimit(q, client, outCap);
    stats_.cacheHits++;
    return dns::finalizeForClient(work.scratch, n, q, co, out, outCap);
  }
  return forward(q, client, nullptr, nullptr, out, outCap, forwarded);
}

// A DNS rewrite (ARCHITECTURE.md §5.7): answered locally, or the alias target's records
// from the cache / upstream wrapped in the CNAME chain.
size_t DnsService::processRewrite(const dns::Query& q, const ClientRef& client, Work& work, uint8_t* out,
                                  size_t outCap, bool* forwarded) {
  stats_.rewritten++;
  const dns::RewriteAnswer& rw = work.rewrite;
  const size_t limit = sizeLimit(q, client, outCap);
  if (rw.end == dns::RewriteAnswer::End::kLoop) {
    stats_.servfail++;
    return dns::buildErrorReply(q, dns::Rcode::kServFail, out, outCap);
  }
  if (!rw.forwards() || q.qtype == dns::kTypeCname) {
    stats_.local++;
    return dns::buildRewriteReply(q, rw, nullptr, 0, limit, out, outCap);
  }
  if (!dns::rewriteTargetQuery(q, rw, work.target)) {
    stats_.servfail++;
    return dns::buildErrorReply(q, dns::Rcode::kServFail, out, outCap);
  }
  size_t n;
  {
    platform::LockGuard g(cacheMutex_);
    n = cache_->lookup(work.target, work.scratch, work.scratchCap);
  }
  if (n) {
    stats_.cacheHits++;
    return dns::buildRewriteReply(q, rw, work.scratch, n, limit, out, outCap);
  }
  return forward(work.target, client, &q, &rw, out, outCap, forwarded);
}

size_t DnsService::forward(const dns::Query& q, const ClientRef& client, const dns::Query* rewriteOf,
                           const dns::RewriteAnswer* rewrite, uint8_t* out, size_t outCap, bool* forwarded) {
  const dns::Query& replyTo = rewriteOf ? *rewriteOf : q;  // what the client asked
  // UDP clients get at most their share of the pool (TCP has per-connection limits).
  const bool udp = client.origin == Origin::kUdp;
  if (udp && !udpInFlight_.tryAcquire(client.addr.sin_addr.s_addr, uxQueueMessagesWaiting(freeQ_))) {
    stats_.servfail++;
    return dns::buildErrorReply(replyTo, dns::Rcode::kServFail, out, outCap);
  }
  uint16_t idx;
  if (xQueueReceive(freeQ_, &idx, 0) != pdTRUE) {
    if (udp) udpInFlight_.release(client.addr.sin_addr.s_addr);
    stats_.servfail++;
    return dns::buildErrorReply(replyTo, dns::Rcode::kServFail, out, outCap);
  }
  Pending& p = pool_[idx];
  p.q = q;
  p.client = client;
  p.replyLen = 0;
  p.rewritten = rewriteOf != nullptr;
  if (p.rewritten) {
    p.clientQ = *rewriteOf;
    p.rewrite = *rewrite;
  }
  if (xQueueSend(upQ_, &idx, 0) != pdTRUE) {
    xQueueSend(freeQ_, &idx, 0);
    if (udp) udpInFlight_.release(client.addr.sin_addr.s_addr);
    stats_.servfail++;
    return dns::buildErrorReply(replyTo, dns::Rcode::kServFail, out, outCap);
  }
  stats_.forwarded++;
  if (forwarded) *forwarded = true;
  return 0;
}

// --------------------------------------------------------------------------------
// dns_io task: UDP/53

void DnsService::ioLoop() {
  esp_task_wdt_add(nullptr);
  const int maxFd = (udpFd_ > udpWakeRxFd_ ? udpFd_ : udpWakeRxFd_) + 1;
  while (true) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(udpFd_, &rfds);
    FD_SET(udpWakeRxFd_, &rfds);
    struct timeval tv = {1, 0};  // wake at least once a second for the watchdog
    const int ready = select(maxFd, &rfds, nullptr, nullptr, &tv);
    esp_task_wdt_reset();
    if (ready < 0) continue;

    if (FD_ISSET(udpWakeRxFd_, &rfds)) drainSocket(udpWakeRxFd_);
    uint16_t idx;
    while (xQueueReceive(udpReplyQ_, &idx, 0) == pdTRUE) {
      Pending& p = pool_[idx];
      if (p.replyLen)
        sendto(udpFd_, p.reply, p.replyLen, 0, reinterpret_cast<const struct sockaddr*>(&p.client.addr),
               sizeof(p.client.addr));
      udpInFlight_.release(p.client.addr.sin_addr.s_addr);
      xQueueSend(freeQ_, &idx, 0);
    }

    if (!FD_ISSET(udpFd_, &rfds)) continue;
    int handled = 0;
    for (; handled < kMaxDatagramsPerWake; handled++) {
      ClientRef c;
      socklen_t fromLen = sizeof(c.addr);
      const int n = recvfrom(udpFd_, udpRx_, sizeof(udpRx_), MSG_DONTWAIT,
                             reinterpret_cast<struct sockaddr*>(&c.addr), &fromLen);
      if (n <= 0) break;
      const size_t r = processQuery(udpRx_, static_cast<size_t>(n), c, udpWork_, udpOut_, sizeof(udpOut_));
      if (r) sendto(udpFd_, udpOut_, r, 0, reinterpret_cast<const struct sockaddr*>(&c.addr), sizeof(c.addr));
    }
    if (handled == kMaxDatagramsPerWake) vTaskDelay(1);  // more waiting: let core 1's other tasks run
  }
}

// --------------------------------------------------------------------------------
// dns_tcp task: TCP/53 (RFC 7766), length-prefixed, pipelined queries allowed

void DnsService::tcpClose(uint8_t i) {
  if (tcp_[i].fd >= 0) close(tcp_[i].fd);
  tcp_[i].fd = -1;
  tcp_[i].rxLen = 0;
  tcp_[i].partialSince = 0;
  tcp_[i].inFlight = 0;
  tcp_[i].gen++;  // late replies for this connection are discarded
}

bool DnsService::tcpWrite(uint8_t i, const uint8_t* msg, size_t len) {
  if (tcp_[i].fd < 0 || len + 2 > sizeof(tcpOut_)) return false;
  util::writeU16Be(tcpOut_, static_cast<uint16_t>(len));
  if (msg != tcpOut_ + 2) memmove(tcpOut_ + 2, msg, len);
  // Each send() is bounded by SO_SNDTIMEO, the whole reply by kTcpWriteBudgetMs, so
  // one reply holds dns_tcp for at most ~1.5 s; feeding first keeps several in a row
  // (pipelined queries, a drained reply queue) inside the 5 s watchdog.
  esp_task_wdt_reset();
  const int fd = tcp_[i].fd;
  const util::SendResult r = util::sendAllWithDeadline(
      len + 2, kTcpWriteBudgetMs, clock_,
      [&](size_t off, size_t n) { return static_cast<long>(send(fd, tcpOut_ + off, n, 0)); });
  if (!r.complete) {
    tcpClose(i);
    return false;
  }
  tcp_[i].lastMs = clock_.monotonicMs();
  return true;
}

void DnsService::tcpAccept() {
  struct sockaddr_in peer;
  socklen_t len = sizeof(peer);
  const int fd = accept(tcpListenFd_, reinterpret_cast<struct sockaddr*>(&peer), &len);
  if (fd < 0) return;
  if (!isPrivateSource(peer)) {
    close(fd);
    stats_.dropped++;
    return;
  }
  uint8_t slot = 0xFF;
  for (uint8_t i = 0; i < cfg_.tcpMaxConns; i++)
    if (tcp_[i].fd < 0) {
      slot = i;
      break;
    }
  if (slot == 0xFF) {
    // Full: evict the least recently active connection rather than refusing, so no
    // client can hold every slot by sending a query just before the idle timeout.
    slot = 0;
    for (uint8_t i = 1; i < cfg_.tcpMaxConns; i++)
      if (tcp_[i].lastMs < tcp_[slot].lastMs) slot = i;
    tcpClose(slot);
  }
  struct timeval tv = {kTcpWriteTimeoutMs / 1000, (kTcpWriteTimeoutMs % 1000) * 1000};
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  tcp_[slot].fd = fd;
  tcp_[slot].peer = peer;
  tcp_[slot].rxLen = 0;
  tcp_[slot].partialSince = 0;
  tcp_[slot].inFlight = 0;
  tcp_[slot].lastMs = clock_.monotonicMs();
}

void DnsService::tcpRead(uint8_t i) {
  TcpConn& c = tcp_[i];
  const int n = recv(c.fd, c.rx + c.rxLen, sizeof(c.rx) - c.rxLen, MSG_DONTWAIT);
  if (n <= 0) {
    tcpClose(i);
    return;
  }
  c.rxLen += static_cast<size_t>(n);
  tcpProcessBuffered(i);
}

void DnsService::tcpProcessBuffered(uint8_t i) {
  TcpConn& c = tcp_[i];
  while (c.fd >= 0 && c.rxLen >= 2) {
    if (c.inFlight >= kTcpMaxInFlightPerConn || tcpPending_ >= kTcpMaxInFlightTotal)
      break;  // stop until replies drain (the connection is not selected meanwhile)
    const size_t msgLen = util::readU16Be(c.rx);
    if (msgLen < dns::kHeaderSize || msgLen + 2 > sizeof(c.rx)) {
      stats_.dropped++;
      tcpClose(i);  // malformed or oversized query: drop the connection
      return;
    }
    if (c.rxLen < msgLen + 2) break;
    ClientRef ref;
    ref.origin = Origin::kTcp;
    ref.addr = c.peer;
    ref.conn = i;
    ref.connGen = c.gen;
    bool forwarded = false;
    const size_t r =
        processQuery(c.rx + 2, msgLen, ref, tcpWork_, tcpOut_ + 2, sizeof(tcpOut_) - 2, &forwarded);
    memmove(c.rx, c.rx + 2 + msgLen, c.rxLen - 2 - msgLen);
    c.rxLen -= 2 + msgLen;
    c.lastMs = clock_.monotonicMs();  // only complete queries count as activity
    if (forwarded) {
      c.inFlight++;
      tcpPending_++;
    }
    if (r) tcpWrite(i, tcpOut_ + 2, r);
  }
  if (c.fd >= 0) c.partialSince = c.rxLen ? (c.partialSince ? c.partialSince : clock_.monotonicMs()) : 0;
}

void DnsService::tcpLoop() {
  esp_task_wdt_add(nullptr);
  while (true) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(tcpListenFd_, &rfds);
    FD_SET(tcpWakeRxFd_, &rfds);
    int maxFd = tcpListenFd_ > tcpWakeRxFd_ ? tcpListenFd_ : tcpWakeRxFd_;
    const bool poolFull = tcpPending_ >= kTcpMaxInFlightTotal;
    for (uint8_t i = 0; i < cfg_.tcpMaxConns; i++)
      if (tcp_[i].fd >= 0 && !poolFull && tcp_[i].inFlight < kTcpMaxInFlightPerConn) {
        FD_SET(tcp_[i].fd, &rfds);
        if (tcp_[i].fd > maxFd) maxFd = tcp_[i].fd;
      }
    struct timeval tv = {1, 0};
    const int ready = select(maxFd + 1, &rfds, nullptr, nullptr, &tv);
    esp_task_wdt_reset();
    if (ready < 0) continue;

    if (FD_ISSET(tcpWakeRxFd_, &rfds)) drainSocket(tcpWakeRxFd_);
    uint16_t idx;
    while (xQueueReceive(tcpReplyQ_, &idx, 0) == pdTRUE) {
      Pending& p = pool_[idx];
      const uint8_t i = p.client.conn;
      if (tcpPending_) tcpPending_--;  // counted until dequeued, even if the connection closed
      if (tcp_[i].fd >= 0 && tcp_[i].gen == p.client.connGen) {
        if (tcp_[i].inFlight) tcp_[i].inFlight--;
        if (p.replyLen) tcpWrite(i, p.reply, p.replyLen);
      }
      xQueueSend(freeQ_, &idx, 0);
    }
    // Queries left buffered while a connection was at its in-flight limit.
    for (uint8_t i = 0; i < cfg_.tcpMaxConns; i++)
      if (tcp_[i].fd >= 0 && tcp_[i].rxLen >= 2 && tcp_[i].inFlight < kTcpMaxInFlightPerConn)
        tcpProcessBuffered(i);
    if (FD_ISSET(tcpListenFd_, &rfds)) tcpAccept();
    for (uint8_t i = 0; i < cfg_.tcpMaxConns; i++)
      if (tcp_[i].fd >= 0 && FD_ISSET(tcp_[i].fd, &rfds)) tcpRead(i);

    const uint64_t now = clock_.monotonicMs();
    for (uint8_t i = 0; i < cfg_.tcpMaxConns; i++) {
      // Upstream answers (or SERVFAILs) within 2.5 s, far below the idle limit, so
      // in-flight queries never need to exempt a connection from these deadlines.
      if (tcp_[i].fd < 0) continue;
      if (now - tcp_[i].lastMs >= cfg_.tcpIdleMs ||
          (tcp_[i].partialSince && now - tcp_[i].partialSince >= kTcpPartialFrameMs))
        tcpClose(i);
    }
  }
}

// --------------------------------------------------------------------------------
// dns_up task

void DnsService::completeSlot(uint16_t idx) {
  const bool tcp = pool_[idx].client.origin == Origin::kTcp;
  xQueueSend(tcp ? tcpReplyQ_ : udpReplyQ_, &idx, portMAX_DELAY);  // capacity == pool size
  const uint8_t one = 1;
  const struct sockaddr_in& to = tcp ? tcpWakeAddr_ : udpWakeAddr_;
  sendto(wakeTxFd_, &one, 1, 0, reinterpret_cast<const struct sockaddr*>(&to), sizeof(to));
}

void DnsService::onAnswer(uint32_t token, const dns::Query& q, const uint8_t* answer, size_t len,
                          const dns::ResponseInfo& info, bool authenticated) {
  // Cache only answers that came over a verified encrypted channel.
  if (authenticated) {
    platform::LockGuard g(cacheMutex_);
    cache_->insert(q, answer, len, info);
  }
  Pending& p = pool_[token];
  const dns::Query& cq = p.rewritten ? p.clientQ : q;  // what the client asked
  const size_t limit = sizeLimit(cq, p.client, cfg_.replyCap);
  if (p.rewritten) {
    // The alias target's answer, wrapped in the CNAME chain for the client's name.
    p.replyLen = static_cast<uint16_t>(
        dns::buildRewriteReply(cq, p.rewrite, answer, len, limit, p.reply, cfg_.replyCap));
  } else {
    dns::ClientReplyOptions co;
    co.authenticatedUpstream = authenticated && cfg_.passAd;
    co.sizeLimit = limit;
    p.replyLen = static_cast<uint16_t>(dns::finalizeForClient(answer, len, q, co, p.reply, cfg_.replyCap));
  }
  if (p.replyLen == 0) {
    stats_.servfail++;
    p.replyLen =
        static_cast<uint16_t>(dns::buildErrorReply(cq, dns::Rcode::kServFail, p.reply, cfg_.replyCap));
  }
  completeSlot(static_cast<uint16_t>(token));
}

void DnsService::onFailure(uint32_t token, const dns::Query& q) {
  Pending& p = pool_[token];
  stats_.servfail++;
  const dns::Query& cq = p.rewritten ? p.clientQ : q;  // echo the client's own question
  p.replyLen = static_cast<uint16_t>(dns::buildErrorReply(cq, dns::Rcode::kServFail, p.reply, cfg_.replyCap));
  completeSlot(static_cast<uint16_t>(token));
}

void DnsService::publishSnapshot() {
  UpstreamSnapshot s;
  s.count = forwarder_->upstreamCount();
  s.plainFallback = forwarder_->plainFallbackActive();
  s.testing = forwarder_->probing() || testRequested_.load();
  for (size_t i = 0; i < s.count; i++) {
    s.status[i] = forwarder_->upstreamStatus(i);
    s.totalOk += s.status[i].stats.ok;
  }
  platform::LockGuard g(snapshotMutex_);
  snapshot_ = s;
}

void DnsService::upstreamLoop() {
  esp_task_wdt_add(nullptr);
  while (true) {
    // Block on new work when idle; just poll the queue while queries are in flight.
    uint16_t idx;
    if (testRequested_.load()) {
      dns::Query q;
      if (dns::makeSelfQuery(kUpstreamTestName, dns::kTypeA, q)) forwarder_->startProbe(q);
      testRequested_.store(false);
      publishSnapshot();  // show "testing" right away
    }
    const bool busy = forwarder_->inFlight() > 0 || forwarder_->probing();
    TickType_t wait = busy ? 0 : pdMS_TO_TICKS(1000);
    while (xQueueReceive(upQ_, &idx, wait) == pdTRUE) {
      wait = 0;
      if (!forwarder_->submit(idx, pool_[idx].q)) onFailure(idx, pool_[idx].q);
      // Each submit() may block up to ForwarderConfig::maxBlockingMs (one connect to
      // an unreachable upstream), so feed per query: draining several queued queries
      // before one feed exceeded the 5 s watchdog and crash-looped the board while
      // the primary upstream was down (found on hardware, 2026-10-15).
      esp_task_wdt_reset();
      if (cfg_.liveness) cfg_.liveness->beat(cfg_.livenessId);
    }
    forwarder_->poll(forwarder_->inFlight() > 0 || forwarder_->probing() ? 10 : 0);
    esp_task_wdt_reset();
    if (cfg_.liveness) cfg_.liveness->beat(cfg_.livenessId);
#ifdef ADBLOCK_SELFTEST
    if (cfg_.selftestHang && cfg_.selftestHang->load() == 1)
      while (true) {  // an I/O livelock: the hardware watchdog stays fed
        esp_task_wdt_reset();
        vTaskDelay(pdMS_TO_TICKS(100));
      }
    if (cfg_.selftestHang && cfg_.selftestHang->load() == 2)
      while (true) vTaskDelay(pdMS_TO_TICKS(100));  // a plain hang: hardware watchdog
#endif

    const uint64_t now = clock_.monotonicMs();
    if (now - lastSnapshotMs_ >= 500) {
      lastSnapshotMs_ = now;
      publishSnapshot();
    }
  }
}

// --------------------------------------------------------------------------------
// Read-side API (web/maintenance tasks)

DnsStats DnsService::stats() const {
  DnsStats s;
  s.queries = stats_.queries.load();
  s.tcpQueries = stats_.tcpQueries.load();
  s.blocked = stats_.blocked.load();
  s.local = stats_.local.load();
  s.cacheHits = stats_.cacheHits.load();
  s.forwarded = stats_.forwarded.load();
  s.servfail = stats_.servfail.load();
  s.errors = stats_.errors.load();
  s.dropped = stats_.dropped.load();
  s.rewritten = stats_.rewritten.load();
  return s;
}

UpstreamSnapshot DnsService::upstreams() const {
  platform::LockGuard g(snapshotMutex_);
  UpstreamSnapshot s = snapshot_;
  // The snapshot can be ~1 s old: a test asked for just now is already "testing".
  if (testRequested_.load()) s.testing = true;
  return s;
}

cache::CacheStats DnsService::cacheStats() {
  platform::LockGuard g(cacheMutex_);
  return cache_->stats();
}

bool DnsService::startUpstreamTest() {
  if (!running_) return false;
  if (upstreams().testing) return false;
  bool expected = false;
  return testRequested_.compare_exchange_strong(expected, true);
}

void DnsService::flushCache() {
  platform::LockGuard g(cacheMutex_);
  cache_->clear();
}

}  // namespace app
