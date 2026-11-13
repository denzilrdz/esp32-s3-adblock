#pragma once
// The DNS server tasks (ARCHITECTURE.md §4):
//
//  dns_io   (core 1, prio 10): owns UDP/53.
//  dns_tcp  (core 0, prio 5):  owns the TCP/53 listener and up to tcpMaxConns
//                              connections (RFC 7766; clients retry here after TC=1).
//  dns_up   (core 1, prio 8):  owns the Forwarder and its DoT/DoH/UDP transports.
//
// dns_io and dns_tcp share one query pipeline (validate, local zones, policy, cache).
// Misses go to dns_up through a fixed slot pool + queue; dns_up writes the reply into
// the slot and hands it back to the task that owns the client's socket, waking it
// through a loopback "self-pipe" socket. Each socket is used by exactly one task (our
// ownership rule; lwIP itself is built with LWIP_NETCONN_FULLDUPLEX).

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <lwip/sockets.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "cache/response_cache.h"
#include "clients/inflight_limiter.h"
#include "diag/liveness.h"
#include "dns/local_zones.h"
#include "dns/message.h"
#include "dns/query_policy.h"
#include "dns/rewrite_reply.h"
#include "hal/clock.h"
#include "hal/logger.h"
#include "hal/random.h"
#include "platform/psram.h"
#include "platform/rtos.h"
#include "upstream/forwarder.h"

namespace app {

struct DnsServiceConfig {
  cache::CacheConfig cache;
  upstream::ForwarderConfig forwarder;
  dns::LocalZoneOptions local;
  uint32_t blockedTtl = 10;
  uint32_t localTtl = 60;
  bool passAd = true;          // pass the DNSSEC AD bit from authenticated upstreams
  uint16_t pendingSlots = 32;  // <= Forwarder::kMaxInFlight
  // Most of those one UDP client may hold at once (0 = half the pool). A router relaying
  // DNS for the whole LAN is one client, so keep this a share, not a small number.
  uint16_t pendingPerClient = 0;
  uint16_t port = 53;
  bool tcpEnabled = true;
  uint8_t tcpMaxConns = 2;  // lwIP has 16 sockets in total; see ARCHITECTURE.md §11
  uint32_t tcpIdleMs = 10000;
  size_t replyCap = upstream::Forwarder::kMaxAnswer;  // per slot; >= 1232
  // Software watchdog for the upstream task (its TLS I/O feeds the hardware one per
  // socket call): beaten once per loop. Optional.
  diag::LivenessMonitor* liveness = nullptr;
  int livenessId = -1;
#ifdef ADBLOCK_SELFTEST
  // 1: spin feeding the hardware watchdog without progress; 2: stop feeding it.
  std::atomic<int>* selftestHang = nullptr;
#endif
};

struct DnsStats {
  uint32_t queries = 0;
  uint32_t tcpQueries = 0;
  uint32_t blocked = 0;
  uint32_t local = 0;
  uint32_t cacheHits = 0;
  uint32_t forwarded = 0;
  uint32_t servfail = 0;
  uint32_t errors = 0;     // FORMERR/NOTIMP/REFUSED replies
  uint32_t dropped = 0;    // non-private source, responses, malformed TCP framing
  uint32_t rewritten = 0;  // answered by a DNS rewrite (also counted as local/cache/forwarded)
};

struct UpstreamSnapshot {
  size_t count = 0;
  bool plainFallback = false;
  bool testing = false;  // an upstream test (startUpstreamTest) is running
  uint32_t totalOk = 0;
  upstream::UpstreamStatus status[upstream::Forwarder::kMaxUpstreams];
};

class DnsService : private upstream::IForwarderSink {
 public:
  DnsService(const DnsServiceConfig& cfg, dns::IQueryPolicy& policy, const hal::IClock& clock,
             hal::IRandom& random, hal::ILogger& log, upstream::ITransport* const* transports,
             size_t transportCount);
  // Lives for the whole uptime (created once in setup(), never destroyed).

  bool start();
  bool running() const { return running_; }

  DnsStats stats() const;
  UpstreamSnapshot upstreams() const;
  cache::CacheStats cacheStats();
  void flushCache();
  // Asks dns_up to test every upstream once (results in upstreams().status[i].probe).
  // False if a test is already running. Any task.
  bool startUpstreamTest();

 private:
  enum class Origin : uint8_t { kUdp, kTcp };

  struct ClientRef {
    Origin origin = Origin::kUdp;
    struct sockaddr_in addr;
    uint8_t conn = 0;      // TCP connection index
    uint32_t connGen = 0;  // detects a reply for a connection that was since reused
  };

  struct Pending {
    dns::Query q;  // what goes upstream (a rewrite's alias target)
    ClientRef client;
    bool rewritten = false;  // then clientQ/rewrite hold the client's query and the chain
    dns::Query clientQ;
    dns::RewriteAnswer rewrite;
    uint16_t replyLen;
    uint8_t* reply;  // cfg_.replyCap bytes
  };

  struct TcpConn {
    int fd = -1;
    uint32_t gen = 0;
    uint64_t lastMs = 0;        // last complete query or reply
    uint64_t partialSince = 0;  // when an incomplete frame started arriving (0 = none)
    uint8_t inFlight = 0;       // forwarded queries awaiting a reply
    struct sockaddr_in peer;
    size_t rxLen = 0;
    uint8_t rx[2 + 512];  // one length-prefixed query (queries over 512 bytes are refused)
  };

  static void ioTaskEntry(void* self);
  static void tcpTaskEntry(void* self);
  static void upstreamTaskEntry(void* self);
  void ioLoop();
  void tcpLoop();
  void upstreamLoop();

  // Per-task working memory for the shared pipeline (kept off the small task stacks).
  struct Work {
    uint8_t* scratch;
    size_t scratchCap;
    dns::RewriteAnswer rewrite;
    dns::Query target;  // a rewrite's alias target
  };

  // Shared pipeline. Returns the length of an immediate reply written to `out`, or
  // 0 if the query was dropped or handed to the upstream task.
  size_t processQuery(const uint8_t* pkt, size_t len, const ClientRef& client, Work& work, uint8_t* out,
                      size_t outCap, bool* forwarded = nullptr);
  size_t processRewrite(const dns::Query& q, const ClientRef& client, Work& work, uint8_t* out, size_t outCap,
                        bool* forwarded);
  // Hands a cache miss to dns_up. `rewriteOf` = the client's query when `q` is a
  // rewrite's alias target. Returns 0, or a SERVFAIL reply in `out` if the pool is full.
  size_t forward(const dns::Query& q, const ClientRef& client, const dns::Query* rewriteOf,
                 const dns::RewriteAnswer* rewrite, uint8_t* out, size_t outCap, bool* forwarded);
  size_t sizeLimit(const dns::Query& q, const ClientRef& client, size_t outCap) const {
    return client.origin == Origin::kTcp ? outCap : q.udpReplyLimit();
  }
  // Pool slots held by TCP queries until their reply is dequeued, including queries
  // from connections that have since closed (dns_tcp task only).
  uint8_t tcpPending_ = 0;
  clients::InFlightLimiter udpInFlight_;  // pool slots held per UDP client (dns_io only)
  bool createWakePair(int& rxFd, struct sockaddr_in& addr);
  void tcpAccept();
  void tcpRead(uint8_t i);
  void tcpProcessBuffered(uint8_t i);
  void tcpClose(uint8_t i);
  bool tcpWrite(uint8_t i, const uint8_t* msg, size_t len);
  void completeSlot(uint16_t idx);  // upstream task: route reply + wake the owner
  void publishSnapshot();

  // IForwarderSink (upstream task)
  void onAnswer(uint32_t token, const dns::Query& q, const uint8_t* answer, size_t len,
                const dns::ResponseInfo& info, bool authenticated) override;
  void onFailure(uint32_t token, const dns::Query& q) override;

  DnsServiceConfig cfg_;
  dns::IQueryPolicy& policy_;
  const hal::IClock& clock_;
  hal::IRandom& random_;
  hal::ILogger& log_;
  upstream::ITransport* const* transports_;
  size_t transportCount_;
  bool running_ = false;

  platform::LargeBuffer cacheMemory_;
  cache::ResponseCache* cache_ = nullptr;
  platform::Mutex cacheMutex_;
  upstream::Forwarder* forwarder_ = nullptr;
  Pending* pool_ = nullptr;
  platform::LargeBuffer poolMemory_;
  platform::LargeBuffer replyMemory_;

  QueueHandle_t freeQ_ = nullptr;      // indices of free pool slots
  QueueHandle_t upQ_ = nullptr;        // dns_io/dns_tcp -> upstream
  QueueHandle_t udpReplyQ_ = nullptr;  // upstream -> dns_io
  QueueHandle_t tcpReplyQ_ = nullptr;  // upstream -> dns_tcp

  int udpFd_ = -1;
  int tcpListenFd_ = -1;
  int udpWakeRxFd_ = -1;  // owned by dns_io
  int tcpWakeRxFd_ = -1;  // owned by dns_tcp
  int wakeTxFd_ = -1;     // owned by dns_up
  struct sockaddr_in udpWakeAddr_;
  struct sockaddr_in tcpWakeAddr_;
  TcpConn tcp_[8];

  struct AtomicStats {
    std::atomic<uint32_t> queries{0}, tcpQueries{0}, blocked{0}, local{0}, cacheHits{0}, forwarded{0},
        servfail{0}, errors{0}, dropped{0}, rewritten{0};
  } stats_;

  mutable platform::Mutex snapshotMutex_;
  UpstreamSnapshot snapshot_;
  uint64_t lastSnapshotMs_ = 0;
  std::atomic<bool> testRequested_{false};

  // Per-task buffers (each touched by one task only).
  uint8_t udpRx_[dns::kMaxUdpPayload + 256];
  uint8_t udpScratch_[upstream::Forwarder::kMaxAnswer];
  uint8_t udpOut_[dns::kMaxUdpPayload];
  uint8_t tcpScratch_[upstream::Forwarder::kMaxAnswer];
  uint8_t tcpOut_[2 + upstream::Forwarder::kMaxAnswer];
  Work udpWork_{udpScratch_, sizeof(udpScratch_), {}, {}};
  Work tcpWork_{tcpScratch_, sizeof(tcpScratch_), {}, {}};
};

}  // namespace app
