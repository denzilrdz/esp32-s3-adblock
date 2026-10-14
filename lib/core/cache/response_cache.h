#pragma once
// TTL-respecting LRU cache of upstream DNS answers.
//
// All memory comes from one caller-provided region (PSRAM on the device), carved into
// an entry pool, hash buckets and a slab of fixed-size payload blocks. Nothing is
// allocated after construction, so the DNS hot path never calls malloc.
//
// Not thread-safe: the owning task serialises access (see src/tasks/).

#include <cstddef>
#include <cstdint>

#include "dns/message.h"
#include "hal/clock.h"

namespace cache {

struct CacheConfig {
  uint32_t maxEntries = 16384;
  size_t arenaBytes = 2 * 1024 * 1024;  // payload slab
  uint32_t minTtl = 0;                  // clamp for positive answers (seconds)
  uint32_t maxTtl = 86400;
  uint32_t maxNegativeTtl = 10800;  // RFC 2308 suggests <= 3 h
  uint32_t noSoaNegativeTtl = 30;   // NXDOMAIN/NODATA without an SOA
  size_t maxPayload = 4096;         // larger answers are not cached
};

struct CacheStats {
  uint64_t hits = 0;
  uint64_t misses = 0;
  uint64_t inserts = 0;
  uint64_t evictions = 0;
  uint32_t entries = 0;
  uint32_t freeBlocks = 0;
};

class ResponseCache {
 public:
  static constexpr size_t kBlockSize = 128;

  // Bytes of memory the constructor needs for this config (8-byte aligned region).
  static size_t requiredBytes(const CacheConfig& cfg);

  ResponseCache(const CacheConfig& cfg, void* memory, const hal::IClock& clock);
  ResponseCache(const ResponseCache&) = delete;
  ResponseCache& operator=(const ResponseCache&) = delete;

  // Stores an upstream answer for `q`. `answer` must already have its OPT stripped and
  // `info` must come from dns::inspectResponse on it. Returns false if the answer is
  // not cacheable (SERVFAIL, TC, TTL 0, too big) or memory could not be freed.
  bool insert(const dns::Query& q, const uint8_t* answer, size_t len, const dns::ResponseInfo& info);

  // On a hit, copies the answer into `out` with every TTL reduced by its age and
  // returns its length. Returns 0 on a miss (expired entries are dropped).
  size_t lookup(const dns::Query& q, uint8_t* out, size_t cap);

  void clear();
  CacheStats stats() const;

 private:
  static constexpr uint32_t kNone = 0xFFFFFFFFu;

  struct Entry {
    uint64_t insertedMs;
    uint64_t expiresMs;
    uint32_t hash;
    uint32_t bucketNext;  // also the free-list link
    uint32_t lruPrev;
    uint32_t lruNext;
    uint32_t firstBlock;
    uint16_t len;
    uint8_t dnssecOk;
    uint8_t used;
  };

  static uint32_t keyHash(const dns::Query& q);
  static uint32_t bucketCountFor(uint32_t maxEntries);
  uint32_t blocksFor(size_t len) const { return static_cast<uint32_t>((len + kBlockSize - 1) / kBlockSize); }

  uint32_t find(const dns::Query& q, uint32_t hash) const;
  bool keyMatches(const Entry& e, const dns::Query& q) const;
  void copyOut(const Entry& e, uint8_t* out) const;
  void remove(uint32_t idx);
  void lruUnlink(uint32_t idx);
  void lruPushFront(uint32_t idx);
  bool evictOne();
  uint32_t ttlFor(const dns::ResponseInfo& info, bool& cacheable) const;

  CacheConfig cfg_;
  const hal::IClock& clock_;
  Entry* entries_;
  uint32_t* buckets_;
  uint32_t* blockNext_;
  uint8_t* blocks_;
  uint32_t bucketCount_;
  uint32_t blockCount_;
  uint32_t freeEntry_ = kNone;
  uint32_t freeBlock_ = kNone;
  uint32_t lruHead_ = kNone;
  uint32_t lruTail_ = kNone;
  CacheStats stats_;
};

}  // namespace cache
