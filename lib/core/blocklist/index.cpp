#include "blocklist/index.h"

#include <thread>

#include "util/bytes.h"

namespace blocklist {

namespace {

// Binary search for `want` in `n` little-endian uint32 values at `p`.
bool searchSuffixes(const uint8_t* p, uint32_t n, uint32_t want) {
  uint32_t lo = 0, hi = n;
  while (lo < hi) {
    const uint32_t mid = lo + (hi - lo) / 2;
    const uint32_t v = util::readU32Le(p + size_t{4} * mid);
    if (v == want) return true;
    if (v < want)
      lo = mid + 1;
    else
      hi = mid;
  }
  return false;
}

}  // namespace

bool MemoryIndex::contains(uint64_t hash48) const {
  const uint32_t b = bucketOf(hash48);
  const uint32_t start = util::readU32Le(table_ + size_t{4} * b);
  const uint32_t end = util::readU32Le(table_ + size_t{4} * (b + 1));
  if (end <= start || end > count_) return false;
  return searchSuffixes(suffixes_ + size_t{4} * start, end - start, suffixOf(hash48));
}

bool FileIndex::contains(uint64_t hash48) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const uint32_t b = bucketOf(hash48);
  uint8_t bounds[8];
  if (!file_->seek(kHeaderSize + size_t{4} * b) || file_->read(bounds, 8) != 8) return false;
  const uint32_t start = util::readU32Le(bounds);
  const uint32_t end = util::readU32Le(bounds + 4);
  if (end <= start || end > count_) return false;
  // Buckets average ~15 entries at 1M names; read the whole bucket in chunks.
  const uint32_t want = suffixOf(hash48);
  uint8_t chunk[256];
  uint32_t i = start;
  if (!file_->seek(kHeaderSize + kBucketTableBytes + size_t{4} * start)) return false;
  while (i < end) {
    const uint32_t n = (end - i) < sizeof(chunk) / 4 ? (end - i) : sizeof(chunk) / 4;
    if (n == 0 || file_->read(chunk, size_t{4} * n) != size_t{4} * n) return false;
    if (searchSuffixes(chunk, n, want)) return true;
    // Sorted: stop once the last value of this chunk is past `want`.
    if (util::readU32Le(chunk + size_t{4} * (n - 1)) > want) return false;
    i += n;
  }
  return false;
}

// Memory ordering: acquire() does "increment readers_[i], then re-read current_" and
// publish() does "store current_, then read readers_[old]". That is a store->load
// (Dekker) handshake: with only acquire/release, both loads may observe stale values,
// letting a reader keep the old index while the writer frees it. These four
// operations therefore use the default sequentially consistent ordering.
IndexHolder::ReadGuard IndexHolder::acquire() const {
  while (true) {
    const int i = current_.load();
    readers_[i].fetch_add(1);
    if (current_.load() == i) return ReadGuard(this, i);
    readers_[i].fetch_sub(1);  // raced with publish: retry
  }
}

void IndexHolder::publish(std::unique_ptr<IIndex> next) {
  std::lock_guard<std::mutex> lock(writer_);
  const int old = current_.load();
  const int fresh = 1 - old;
  // The spare slot was emptied by the previous publish; wait out any reader that
  // briefly touched it while retrying acquire().
  while (readers_[fresh].load() != 0) wait_ ? wait_() : std::this_thread::yield();
  slots_[fresh] = std::move(next);
  current_.store(fresh);
  while (readers_[old].load() != 0) wait_ ? wait_() : std::this_thread::yield();
  slots_[old].reset();
}

uint32_t IndexHolder::count() const {
  ReadGuard g = acquire();
  return g.get() ? g.get()->count() : 0;
}

}  // namespace blocklist
