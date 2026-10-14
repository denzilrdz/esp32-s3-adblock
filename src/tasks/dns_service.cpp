#include "tasks/dns_service.h"

#include <esp_task_wdt.h>

#include <cstring>
#include <new>

namespace app {

using hal::LogLevel;

namespace {

constexpr const char* kTag = "dns";
constexpr int kIoPriority = 10;
constexpr int kUpstreamPriority = 8;
constexpr uint32_t kIoStack = 6144;
constexpr uint32_t kUpstreamStack = 12288;  // TLS handshake needs headroom
constexpr int kDnsCore = 1;
constexpr int kMaxDatagramsPerWake = 16;

// Only answer the LAN: RFC 1918, loopback and link-local sources. Prevents the
// device from becoming an open resolver if port 53 is ever exposed.
bool isPrivateSource(const struct sockaddr_in& a) {
  const uint32_t ip = ntohl(a.sin_addr.s_addr);
  return (ip >> 24) == 10 || (ip >> 20) == (172u << 4 | 1) || (ip >> 16) == (192u << 8 | 168) ||
         (ip >> 24) == 127 || (ip >> 16) == (169u << 8 | 254);
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
  memset(&wakeAddr_, 0, sizeof(wakeAddr_));
}

bool DnsService::start() {
  // Large, long-lived allocations happen once here (PSRAM when available).
  cacheMemory_ = platform::makeLargeBuffer(cache::ResponseCache::requiredBytes(cfg_.cache));
  poolMemory_ = platform::makeLargeBuffer(sizeof(Pending) * cfg_.pendingSlots);
  void* fwdMemory = platform::allocLarge(sizeof(upstream::Forwarder));
  void* cacheObj = platform::allocLarge(sizeof(cache::ResponseCache));
  if (!cacheMemory_ || !poolMemory_ || !fwdMemory || !cacheObj) {
    log_.log(LogLevel::kError, kTag, "out of memory for cache/pool");
    return false;
  }
  cache_ = new (cacheObj) cache::ResponseCache(cfg_.cache, cacheMemory_.get(), clock_);
  forwarder_ = new (fwdMemory) upstream::Forwarder(cfg_.forwarder, transports_, transportCount_, clock_,
                                                    random_, log_, *this);
  pool_ = reinterpret_cast<Pending*>(poolMemory_.get());

  freeQ_ = xQueueCreate(cfg_.pendingSlots, sizeof(uint16_t));
  upQ_ = xQueueCreate(cfg_.pendingSlots, sizeof(uint16_t));
  replyQ_ = xQueueCreate(cfg_.pendingSlots, sizeof(uint16_t));
  if (!freeQ_ || !upQ_ || !replyQ_) return false;
  for (uint16_t i = 0; i < cfg_.pendingSlots; i++) xQueueSend(freeQ_, &i, 0);

  // UDP/53 for clients.
  udpFd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg_.port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (udpFd_ < 0 || bind(udpFd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
    log_.log(LogLevel::kError, kTag, "cannot bind UDP port %u", cfg_.port);
    return false;
  }

  // Self-pipe: dns_io sleeps in select() on both sockets; the upstream task sends a
  // byte to 127.0.0.1:<wake port> when a reply is ready.
  wakeRxFd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  wakeTxFd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  wakeAddr_.sin_family = AF_INET;
  wakeAddr_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  wakeAddr_.sin_port = 0;  // ephemeral
  socklen_t len = sizeof(wakeAddr_);
  if (wakeRxFd_ < 0 || wakeTxFd_ < 0 ||
      bind(wakeRxFd_, reinterpret_cast<struct sockaddr*>(&wakeAddr_), sizeof(wakeAddr_)) != 0 ||
      getsockname(wakeRxFd_, reinterpret_cast<struct sockaddr*>(&wakeAddr_), &len) != 0) {
    log_.log(LogLevel::kError, kTag, "cannot create wake socket");
    return false;
  }

  if (xTaskCreatePinnedToCore(ioTaskEntry, "dns_io", kIoStack, this, kIoPriority, nullptr, kDnsCore) != pdPASS ||
      xTaskCreatePinnedToCore(upstreamTaskEntry, "dns_up", kUpstreamStack, this, kUpstreamPriority, nullptr,
                              kDnsCore) != pdPASS) {
    log_.log(LogLevel::kError, kTag, "cannot start DNS tasks");
    return false;
  }
  log_.log(LogLevel::kInfo, kTag, "listening on UDP %u (%u upstreams, %u-entry cache)", cfg_.port,
           static_cast<unsigned>(transportCount_), static_cast<unsigned>(cfg_.cache.maxEntries));
  return true;
}

void DnsService::ioTaskEntry(void* self) { static_cast<DnsService*>(self)->ioLoop(); }
void DnsService::upstreamTaskEntry(void* self) { static_cast<DnsService*>(self)->upstreamLoop(); }

// --------------------------------------------------------------------------------
// dns_io task

void DnsService::sendTo(const uint8_t* data, size_t len, const struct sockaddr_in& to) {
  if (len == 0) return;
  sendto(udpFd_, data, len, 0, reinterpret_cast<const struct sockaddr*>(&to), sizeof(to));
}

void DnsService::ioLoop() {
  esp_task_wdt_add(nullptr);
  const int maxFd = (udpFd_ > wakeRxFd_ ? udpFd_ : wakeRxFd_) + 1;
  while (true) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(udpFd_, &rfds);
    FD_SET(wakeRxFd_, &rfds);
    struct timeval tv = {1, 0};  // wake at least once a second for the watchdog
    const int ready = select(maxFd, &rfds, nullptr, nullptr, &tv);
    esp_task_wdt_reset();
    if (ready < 0) continue;

    if (FD_ISSET(wakeRxFd_, &rfds)) {
      uint8_t drain[16];
      while (recv(wakeRxFd_, drain, sizeof(drain), MSG_DONTWAIT) > 0) {
      }
    }
    // Replies prepared by the upstream task.
    uint16_t idx;
    while (xQueueReceive(replyQ_, &idx, 0) == pdTRUE) {
      Pending& p = pool_[idx];
      sendTo(p.reply, p.replyLen, p.client);
      xQueueSend(freeQ_, &idx, 0);
    }

    if (FD_ISSET(udpFd_, &rfds)) {
      for (int i = 0; i < kMaxDatagramsPerWake; i++) {
        struct sockaddr_in from;
        socklen_t fromLen = sizeof(from);
        const int n = recvfrom(udpFd_, ioBuf_, sizeof(ioBuf_), MSG_DONTWAIT,
                               reinterpret_cast<struct sockaddr*>(&from), &fromLen);
        if (n <= 0) break;
        handleDatagram(ioBuf_, static_cast<size_t>(n), from);
      }
    }
  }
}

void DnsService::handleDatagram(const uint8_t* pkt, size_t len, const struct sockaddr_in& from) {
  stats_.queries++;
  if (!isPrivateSource(from)) {
    stats_.dropped++;
    return;
  }
  dns::Query q;
  const dns::ParseStatus st = dns::parseQuery(pkt, len, q);
  dns::Rcode errorRcode = dns::Rcode::kNoError;
  switch (st) {
    case dns::ParseStatus::kOk: break;
    case dns::ParseStatus::kDrop: stats_.dropped++; return;
    case dns::ParseStatus::kFormErr: errorRcode = dns::Rcode::kFormErr; break;
    case dns::ParseStatus::kNotImp: errorRcode = dns::Rcode::kNotImp; break;
    case dns::ParseStatus::kRefused: errorRcode = dns::Rcode::kRefused; break;
    case dns::ParseStatus::kBadVers: errorRcode = dns::Rcode::kBadVers; break;
  }
  if (st == dns::ParseStatus::kOk && q.qtype == dns::kTypeAny) errorRcode = dns::Rcode::kNotImp;
  if (errorRcode != dns::Rcode::kNoError) {
    stats_.errors++;
    sendTo(ioOut_, dns::buildErrorReply(q, errorRcode, ioOut_, sizeof(ioOut_)), from);
    return;
  }

  // Local names never leave the device.
  switch (dns::classifyLocal(q.qname, q.qnameLen, cfg_.local)) {
    case dns::LocalAnswer::kLocalhost: {
      static const uint8_t v4[4] = {127, 0, 0, 1};
      static const uint8_t v6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
      stats_.local++;
      sendTo(ioOut_, dns::buildAddressReply(q, v4, v6, cfg_.localTtl, ioOut_, sizeof(ioOut_)), from);
      return;
    }
    case dns::LocalAnswer::kNxDomain:
      stats_.local++;
      sendTo(ioOut_, dns::buildNegativeReply(q, dns::Rcode::kNxDomain, cfg_.localTtl, ioOut_, sizeof(ioOut_)),
             from);
      return;
    case dns::LocalAnswer::kNone: break;
  }

  const dns::PolicyAction action = policy_.decide(q, from.sin_addr.s_addr);
  if (action != dns::PolicyAction::kForward) {
    dns::BlockedReplyOptions opt;
    opt.ttl = cfg_.blockedTtl;
    opt.ede = action == dns::PolicyAction::kBan ? dns::kEdeFiltered : dns::kEdeBlocked;
    stats_.blocked++;
    sendTo(ioOut_, dns::buildBlockedReply(q, opt, ioOut_, sizeof(ioOut_)), from);
    return;
  }

  // Cache hit: only answers from authenticated upstreams are cached, so AD may pass.
  size_t n;
  {
    platform::LockGuard g(cacheMutex_);
    n = cache_->lookup(q, ioBuf_, sizeof(ioBuf_));
  }
  if (n) {
    dns::ClientReplyOptions co;
    co.authenticatedUpstream = true;
    co.sizeLimit = q.udpReplyLimit();
    stats_.cacheHits++;
    sendTo(ioOut_, dns::finalizeForClient(ioBuf_, n, q, co, ioOut_, sizeof(ioOut_)), from);
    return;
  }

  // Miss: hand over to the upstream task.
  uint16_t idx;
  if (xQueueReceive(freeQ_, &idx, 0) != pdTRUE) {
    stats_.servfail++;
    sendTo(ioOut_, dns::buildErrorReply(q, dns::Rcode::kServFail, ioOut_, sizeof(ioOut_)), from);
    return;
  }
  Pending& p = pool_[idx];
  p.q = q;
  p.client = from;
  p.replyLen = 0;
  if (xQueueSend(upQ_, &idx, 0) != pdTRUE) {
    xQueueSend(freeQ_, &idx, 0);
    stats_.servfail++;
    sendTo(ioOut_, dns::buildErrorReply(q, dns::Rcode::kServFail, ioOut_, sizeof(ioOut_)), from);
    return;
  }
  stats_.forwarded++;
}

// --------------------------------------------------------------------------------
// upstream task

void DnsService::completeSlot(uint16_t idx) {
  xQueueSend(replyQ_, &idx, portMAX_DELAY);  // capacity == pool size: never blocks
  const uint8_t one = 1;
  sendto(wakeTxFd_, &one, 1, 0, reinterpret_cast<const struct sockaddr*>(&wakeAddr_), sizeof(wakeAddr_));
}

void DnsService::onAnswer(uint32_t token, const dns::Query& q, const uint8_t* answer, size_t len,
                          const dns::ResponseInfo& info, bool authenticated) {
  // Cache only answers that came over a verified encrypted channel.
  if (authenticated) {
    platform::LockGuard g(cacheMutex_);
    cache_->insert(q, answer, len, info);
  }
  Pending& p = pool_[token];
  dns::ClientReplyOptions co;
  co.authenticatedUpstream = authenticated;
  co.sizeLimit = q.udpReplyLimit();
  p.replyLen = static_cast<uint16_t>(dns::finalizeForClient(answer, len, q, co, p.reply, sizeof(p.reply)));
  if (p.replyLen == 0) {
    stats_.servfail++;
    p.replyLen = static_cast<uint16_t>(dns::buildErrorReply(q, dns::Rcode::kServFail, p.reply, sizeof(p.reply)));
  }
  completeSlot(static_cast<uint16_t>(token));
}

void DnsService::onFailure(uint32_t token, const dns::Query& q) {
  Pending& p = pool_[token];
  stats_.servfail++;
  p.replyLen = static_cast<uint16_t>(dns::buildErrorReply(q, dns::Rcode::kServFail, p.reply, sizeof(p.reply)));
  completeSlot(static_cast<uint16_t>(token));
}

void DnsService::publishSnapshot() {
  UpstreamSnapshot s;
  s.count = forwarder_->upstreamCount();
  s.plainFallback = forwarder_->plainFallbackActive();
  for (size_t i = 0; i < s.count; i++) s.status[i] = forwarder_->upstreamStatus(i);
  platform::LockGuard g(snapshotMutex_);
  snapshot_ = s;
}

void DnsService::upstreamLoop() {
  esp_task_wdt_add(nullptr);
  while (true) {
    // Block on new work when idle; just poll the queue while queries are in flight.
    const bool busy = forwarder_->inFlight() > 0;
    uint16_t idx;
    TickType_t wait = busy ? 0 : pdMS_TO_TICKS(1000);
    while (xQueueReceive(upQ_, &idx, wait) == pdTRUE) {
      wait = 0;
      if (!forwarder_->submit(idx, pool_[idx].q)) onFailure(idx, pool_[idx].q);
    }
    forwarder_->poll(forwarder_->inFlight() > 0 ? 10 : 0);
    esp_task_wdt_reset();

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
  s.blocked = stats_.blocked.load();
  s.local = stats_.local.load();
  s.cacheHits = stats_.cacheHits.load();
  s.forwarded = stats_.forwarded.load();
  s.servfail = stats_.servfail.load();
  s.errors = stats_.errors.load();
  s.dropped = stats_.dropped.load();
  return s;
}

UpstreamSnapshot DnsService::upstreams() const {
  platform::LockGuard g(snapshotMutex_);
  return snapshot_;
}

cache::CacheStats DnsService::cacheStats() {
  platform::LockGuard g(cacheMutex_);
  return cache_->stats();
}

void DnsService::flushCache() {
  platform::LockGuard g(cacheMutex_);
  cache_->clear();
}

}  // namespace app
