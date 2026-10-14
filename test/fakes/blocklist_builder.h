#pragma once
// Builds v2 blocklist files in memory for tests (mirrors tools/build_blocklist.py).

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "blocklist/format.h"
#include "blocklist/hash.h"
#include "util/bytes.h"
#include "util/crc32.h"

namespace testbl {

using Bytes = std::vector<uint8_t>;

inline Bytes buildFromHashes(std::vector<uint64_t> hashes, int64_t buildTime = 1792000000) {
  std::sort(hashes.begin(), hashes.end());
  hashes.erase(std::unique(hashes.begin(), hashes.end()), hashes.end());
  const uint32_t n = static_cast<uint32_t>(hashes.size());
  Bytes payload(blocklist::kBucketTableBytes + size_t{4} * n);
  // Sorting by full 48-bit value sorts by (bucket, suffix).
  std::vector<uint32_t> start(blocklist::kBucketTableEntries, 0);
  for (uint64_t h : hashes) start[blocklist::bucketOf(h) + 1]++;
  for (size_t b = 1; b < start.size(); b++) start[b] += start[b - 1];
  for (size_t b = 0; b < start.size(); b++) util::writeU32Le(payload.data() + 4 * b, start[b]);
  for (uint32_t i = 0; i < n; i++)
    util::writeU32Le(payload.data() + blocklist::kBucketTableBytes + size_t{4} * i,
                     blocklist::suffixOf(hashes[i]));
  Bytes out(blocklist::kHeaderSize);
  blocklist::writeHeader(out.data(), n, util::crc32(payload.data(), payload.size()), buildTime);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

inline Bytes build(const std::vector<std::string>& names, int64_t buildTime = 1792000000) {
  std::vector<uint64_t> hashes;
  for (const auto& n : names) hashes.push_back(blocklist::hashDomain(n.data(), n.size()));
  return buildFromHashes(hashes, buildTime);
}

// n synthetic names: "d<i>.example<i%7>.com"
inline std::vector<std::string> syntheticNames(size_t n, const char* prefix = "d") {
  std::vector<std::string> v;
  v.reserve(n);
  for (size_t i = 0; i < n; i++)
    v.push_back(std::string(prefix) + std::to_string(i) + ".example" + std::to_string(i % 7) + ".com");
  return v;
}

// Recomputes the header CRC after a test deliberately edits the payload.
inline void fixCrc(Bytes& f) {
  const uint32_t crc = util::crc32(f.data() + blocklist::kHeaderSize, f.size() - blocklist::kHeaderSize);
  util::writeU32Le(f.data() + 12, crc);
}

}  // namespace testbl
