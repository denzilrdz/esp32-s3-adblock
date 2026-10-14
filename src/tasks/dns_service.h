#pragma once
// The DNS server: two FreeRTOS tasks on core 1 (ARCHITECTURE.md §4).
//
//  dns_io   (prio 10): owns UDP/53. Validates queries, applies local zones and the
//                      policy (blocklist), serves cache hits, and hands misses to the
//                      upstream task through a fixed pool + queue. Never blocks except
//                      in select(). Sends every reply (one task per socket).
//  upstream (prio 8):  owns the Forwarder and its transports (DoT/DoH/UDP). Inserts
//                      answers into the cache, builds the client reply in the pool
//                      slot, queues it back, and wakes dns_io via a loopback socket.

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <lwip/sockets.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "cache/response_cache.h"
#include "dns/local_zones.h"
#include "dns/message.h"
#include "dns/query_policy.h"
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
  uint16_t pendingSlots = 32;  // <= Forwarder::kMaxInFlight
  uint16_t port = 53;
};

struct DnsStats {
  uint32_t queries = 0;
  uint32_t blocked = 0;
  uint32_t local = 0;
  uint32_t cacheHits = 0;
  uint32_t forwarded = 0;
  uint32_t servfail = 0;
  uint32_t errors = 0;   // FORMERR/NOTIMP/REFUSED replies
  uint32_t dropped = 0;  // non-private source, responses, pool full
};

struct UpstreamSnapshot {
  size_t count = 0;
  bool plainFallback = false;
  upstream::UpstreamStatus status[upstream::Forwarder::kMaxUpstreams];
};

class DnsService : private upstream::IForwarderSink {
 public:
  DnsService(const DnsServiceConfig& cfg, dns::IQueryPolicy& policy, const hal::IClock& clock,
             hal::IRandom& random, hal::ILogger& log, upstream::ITransport* const* transports,
             size_t transportCount);
  // Lives for the whole uptime (created once in setup(), never destroyed).

  bool start();

  DnsStats stats() const;
  UpstreamSnapshot upstreams() const;
  cache::CacheStats cacheStats();
  void flushCache();

 private:
  struct Pending {
    dns::Query q;
    struct sockaddr_in client;
    uint16_t replyLen;
    uint8_t reply[dns::kMaxUdpPayload];
  };

  static void ioTaskEntry(void* self);
  static void upstreamTaskEntry(void* self);
  void ioLoop();
  void upstreamLoop();
  void handleDatagram(const uint8_t* pkt, size_t len, const struct sockaddr_in& from);
  void sendTo(const uint8_t* data, size_t len, const struct sockaddr_in& to);
  void completeSlot(uint16_t idx);  // upstream task: queue reply + wake dns_io
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

  platform::LargeBuffer cacheMemory_;
  cache::ResponseCache* cache_ = nullptr;
  platform::Mutex cacheMutex_;
  upstream::Forwarder* forwarder_ = nullptr;
  Pending* pool_ = nullptr;
  platform::LargeBuffer poolMemory_;

  QueueHandle_t freeQ_ = nullptr;   // indices of free pool slots
  QueueHandle_t upQ_ = nullptr;     // dns_io -> upstream: slot index
  QueueHandle_t replyQ_ = nullptr;  // upstream -> dns_io: slot index with a reply

  int udpFd_ = -1;
  int wakeRxFd_ = -1;  // owned by dns_io
  int wakeTxFd_ = -1;  // owned by upstream task
  struct sockaddr_in wakeAddr_;

  struct AtomicStats {
    std::atomic<uint32_t> queries{0}, blocked{0}, local{0}, cacheHits{0}, forwarded{0},
        servfail{0}, errors{0}, dropped{0};
  } stats_;

  mutable platform::Mutex snapshotMutex_;
  UpstreamSnapshot snapshot_;
  uint64_t lastSnapshotMs_ = 0;

  uint8_t ioBuf_[dns::kMaxUdpPayload + 256];  // dns_io receive buffer
  uint8_t ioOut_[dns::kMaxUdpPayload];        // dns_io reply buffer
};

}  // namespace app
