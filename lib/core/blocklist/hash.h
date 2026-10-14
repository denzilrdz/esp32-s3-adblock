#pragma once
// Domain hashing for the blocklist. MUST match tools/build_blocklist.py:
// FNV-1a 64 over the lowercase name (no trailing dot), truncated to 48 bits.
// The top 16 of those 48 bits select the bucket; the low 32 bits are stored.

#include <cstddef>
#include <cstdint>

namespace blocklist {

constexpr unsigned kHashBits = 48;
constexpr unsigned kPrefixBits = 16;
constexpr uint32_t kBucketCount = 1u << kPrefixBits;
constexpr uint64_t kHashMask = (1ull << kHashBits) - 1;

inline uint64_t hashDomain(const char* name, size_t len) {
  uint64_t h = 0xcbf29ce484222325ull;
  for (size_t i = 0; i < len; i++) {
    h ^= static_cast<uint8_t>(name[i]);
    h *= 0x100000001b3ull;
  }
  return h & kHashMask;
}

inline uint32_t bucketOf(uint64_t hash48) {
  return static_cast<uint32_t>(hash48 >> 32);
}
inline uint32_t suffixOf(uint64_t hash48) {
  return static_cast<uint32_t>(hash48);
}

}  // namespace blocklist
