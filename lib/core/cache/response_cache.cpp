#include "cache/response_cache.h"

#include <cstring>

#include "util/bytes.h"

namespace cache {

namespace {

size_t alignUp(size_t n) {
  return (n + 7) & ~static_cast<size_t>(7);
}

}  // namespace

uint32_t ResponseCache::bucketCountFor(uint32_t maxEntries) {
  uint32_t n = 1;
  while (n < maxEntries) n <<= 1;  // load factor <= 1 with chaining
  return n;
}

size_t ResponseCache::requiredBytes(const CacheConfig& cfg) {
  const size_t blocks = cfg.arenaBytes / kBlockSize;
  return alignUp(sizeof(Entry) * cfg.maxEntries) +
         alignUp(sizeof(uint32_t) * bucketCountFor(cfg.maxEntries)) + alignUp(sizeof(uint32_t) * blocks) +
         blocks * kBlockSize;
}

ResponseCache::ResponseCache(const CacheConfig& cfg, void* memory, const hal::IClock& clock)
    : cfg_(cfg), clock_(clock) {
  auto* p = static_cast<uint8_t*>(memory);
  bucketCount_ = bucketCountFor(cfg.maxEntries);
  blockCount_ = static_cast<uint32_t>(cfg.arenaBytes / kBlockSize);
  entries_ = reinterpret_cast<Entry*>(p);
  p += alignUp(sizeof(Entry) * cfg.maxEntries);
  buckets_ = reinterpret_cast<uint32_t*>(p);
  p += alignUp(sizeof(uint32_t) * bucketCount_);
  blockNext_ = reinterpret_cast<uint32_t*>(p);
  p += alignUp(sizeof(uint32_t) * blockCount_);
  blocks_ = p;
  clear();
}

void ResponseCache::clear() {
  for (uint32_t i = 0; i < bucketCount_; i++) buckets_[i] = kNone;
  for (uint32_t i = 0; i < cfg_.maxEntries; i++) {
    entries_[i] = Entry{};
    entries_[i].bucketNext = (i + 1 < cfg_.maxEntries) ? i + 1 : kNone;
  }
  freeEntry_ = cfg_.maxEntries ? 0 : kNone;
  for (uint32_t i = 0; i < blockCount_; i++) blockNext_[i] = (i + 1 < blockCount_) ? i + 1 : kNone;
  freeBlock_ = blockCount_ ? 0 : kNone;
  lruHead_ = lruTail_ = kNone;
  stats_.entries = 0;
  stats_.freeBlocks = blockCount_;
}

CacheStats ResponseCache::stats() const {
  return stats_;
}

uint32_t ResponseCache::keyHash(const dns::Query& q) {
  uint32_t h = 2166136261u;  // FNV-1a 32 over (wire name, type, class, DO)
  auto mix = [&h](uint8_t b) { h = (h ^ b) * 16777619u; };
  for (uint8_t i = 0; i < q.qnameWireLen; i++) mix(q.qnameWire[i]);
  mix(static_cast<uint8_t>(q.qtype >> 8));
  mix(static_cast<uint8_t>(q.qtype));
  mix(static_cast<uint8_t>(q.qclass >> 8));
  mix(static_cast<uint8_t>(q.qclass));
  mix(q.edns.dnssecOk ? 1 : 0);
  return h;
}

bool ResponseCache::keyMatches(const Entry& e, const dns::Query& q) const {
  if ((e.dnssecOk != 0) != q.edns.dnssecOk) return false;
  // The key is the stored answer's own question section (always in the first block(s)).
  uint8_t head[dns::kHeaderSize + dns::kMaxNameWire + 4];
  size_t n = e.len < sizeof(head) ? e.len : sizeof(head);
  size_t copied = 0;
  for (uint32_t b = e.firstBlock; b != kNone && copied < n; b = blockNext_[b]) {
    size_t chunk = n - copied < kBlockSize ? n - copied : kBlockSize;
    memcpy(head + copied, blocks_ + static_cast<size_t>(b) * kBlockSize, chunk);
    copied += chunk;
  }
  const size_t nameEnd = dns::skipName(head, n, dns::kHeaderSize);
  if (nameEnd == 0 || nameEnd > n || n - nameEnd < 4) return false;  // overflow-safe
  if (!dns::nameEquals(head, n, dns::kHeaderSize, q.qnameWire, q.qnameWireLen)) return false;
  return util::readU16Be(head + nameEnd) == q.qtype && util::readU16Be(head + nameEnd + 2) == q.qclass;
}

uint32_t ResponseCache::find(const dns::Query& q, uint32_t hash) const {
  for (uint32_t i = buckets_[hash & (bucketCount_ - 1)]; i != kNone; i = entries_[i].bucketNext)
    if (entries_[i].hash == hash && keyMatches(entries_[i], q)) return i;
  return kNone;
}

void ResponseCache::lruUnlink(uint32_t idx) {
  Entry& e = entries_[idx];
  if (e.lruPrev != kNone)
    entries_[e.lruPrev].lruNext = e.lruNext;
  else
    lruHead_ = e.lruNext;
  if (e.lruNext != kNone)
    entries_[e.lruNext].lruPrev = e.lruPrev;
  else
    lruTail_ = e.lruPrev;
  e.lruPrev = e.lruNext = kNone;
}

void ResponseCache::lruPushFront(uint32_t idx) {
  Entry& e = entries_[idx];
  e.lruPrev = kNone;
  e.lruNext = lruHead_;
  if (lruHead_ != kNone) entries_[lruHead_].lruPrev = idx;
  lruHead_ = idx;
  if (lruTail_ == kNone) lruTail_ = idx;
}

void ResponseCache::remove(uint32_t idx) {
  Entry& e = entries_[idx];
  // Unlink from its bucket chain.
  uint32_t* link = &buckets_[e.hash & (bucketCount_ - 1)];
  while (*link != kNone && *link != idx) link = &entries_[*link].bucketNext;
  if (*link == idx) *link = e.bucketNext;
  lruUnlink(idx);
  // Return payload blocks to the free list.
  uint32_t b = e.firstBlock;
  while (b != kNone) {
    uint32_t next = blockNext_[b];
    blockNext_[b] = freeBlock_;
    freeBlock_ = b;
    stats_.freeBlocks++;
    b = next;
  }
  e = Entry{};
  e.bucketNext = freeEntry_;
  freeEntry_ = idx;
  stats_.entries--;
}

bool ResponseCache::evictOne() {
  if (lruTail_ == kNone) return false;
  remove(lruTail_);
  stats_.evictions++;
  return true;
}

uint32_t ResponseCache::ttlFor(const dns::ResponseInfo& info, bool& cacheable) const {
  cacheable = false;
  if (info.flags & dns::flag::kTc) return 0;
  const bool nodata = info.rcode == static_cast<uint16_t>(dns::Rcode::kNoError) && info.an == 0;
  const bool nxdomain = info.rcode == static_cast<uint16_t>(dns::Rcode::kNxDomain);
  uint32_t ttl;
  if (nodata || nxdomain) {
    ttl = info.hasSoa ? info.negativeTtl : cfg_.noSoaNegativeTtl;
    if (ttl > cfg_.maxNegativeTtl) ttl = cfg_.maxNegativeTtl;
  } else if (info.rcode == static_cast<uint16_t>(dns::Rcode::kNoError)) {
    ttl = info.minTtl;
    if (ttl < cfg_.minTtl) ttl = cfg_.minTtl;
    if (ttl > cfg_.maxTtl) ttl = cfg_.maxTtl;
  } else {
    return 0;  // SERVFAIL, REFUSED, ...: never cached
  }
  cacheable = ttl > 0;
  return ttl;
}

bool ResponseCache::insert(const dns::Query& q, const uint8_t* answer, size_t len,
                           const dns::ResponseInfo& info) {
  if (!q.hasQuestion || len < dns::kHeaderSize || len > cfg_.maxPayload || info.hasOpt) return false;
  // Defence in depth against poisoning: only store an answer whose own question is
  // exactly the query it is filed under (the forwarder already checks this too).
  if (!dns::responseMatches(answer, len, util::readU16Be(answer), q)) return false;
  bool cacheable;
  const uint32_t ttl = ttlFor(info, cacheable);
  if (!cacheable) return false;
  const uint32_t need = blocksFor(len);
  if (need > blockCount_ || cfg_.maxEntries == 0) return false;

  const uint32_t hash = keyHash(q);
  const uint32_t existing = find(q, hash);
  if (existing != kNone) remove(existing);
  while (freeEntry_ == kNone || stats_.freeBlocks < need)
    if (!evictOne()) return false;

  const uint32_t idx = freeEntry_;
  Entry& e = entries_[idx];
  freeEntry_ = e.bucketNext;

  // Copy the payload into a chain of blocks.
  uint32_t first = kNone, prev = kNone;
  size_t copied = 0;
  for (uint32_t i = 0; i < need; i++) {
    const uint32_t b = freeBlock_;
    freeBlock_ = blockNext_[b];
    stats_.freeBlocks--;
    blockNext_[b] = kNone;
    const size_t chunk = len - copied < kBlockSize ? len - copied : kBlockSize;
    memcpy(blocks_ + static_cast<size_t>(b) * kBlockSize, answer + copied, chunk);
    copied += chunk;
    if (prev == kNone)
      first = b;
    else
      blockNext_[prev] = b;
    prev = b;
  }

  const uint64_t now = clock_.monotonicMs();
  e.insertedMs = now;
  e.expiresMs = now + static_cast<uint64_t>(ttl) * 1000;
  e.hash = hash;
  e.firstBlock = first;
  e.len = static_cast<uint16_t>(len);
  e.dnssecOk = q.edns.dnssecOk ? 1 : 0;
  e.used = 1;
  e.bucketNext = buckets_[hash & (bucketCount_ - 1)];
  buckets_[hash & (bucketCount_ - 1)] = idx;
  e.lruPrev = e.lruNext = kNone;
  lruPushFront(idx);
  stats_.entries++;
  stats_.inserts++;
  return true;
}

void ResponseCache::copyOut(const Entry& e, uint8_t* out) const {
  size_t copied = 0;
  for (uint32_t b = e.firstBlock; b != kNone && copied < e.len; b = blockNext_[b]) {
    const size_t chunk = e.len - copied < kBlockSize ? e.len - copied : kBlockSize;
    memcpy(out + copied, blocks_ + static_cast<size_t>(b) * kBlockSize, chunk);
    copied += chunk;
  }
}

size_t ResponseCache::lookup(const dns::Query& q, uint8_t* out, size_t cap) {
  if (!q.hasQuestion) return 0;
  const uint32_t idx = find(q, keyHash(q));
  if (idx == kNone) {
    stats_.misses++;
    return 0;
  }
  Entry& e = entries_[idx];
  const uint64_t now = clock_.monotonicMs();
  if (now >= e.expiresMs || e.len > cap) {
    if (now >= e.expiresMs) remove(idx);
    stats_.misses++;
    return 0;
  }
  copyOut(e, out);
  const uint32_t age = static_cast<uint32_t>((now - e.insertedMs) / 1000);
  if (age && !dns::ageTtls(out, e.len, age)) {
    remove(idx);  // cannot happen for answers that passed inspectResponse
    stats_.misses++;
    return 0;
  }
  lruUnlink(idx);
  lruPushFront(idx);
  stats_.hits++;
  return e.len;
}

}  // namespace cache
