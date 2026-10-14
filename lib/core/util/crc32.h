#pragma once
// CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) — same as Python's zlib.crc32.

#include <cstddef>
#include <cstdint>

namespace util {

// Start with crc = 0 and feed chunks: crc = crc32Update(crc, chunk, n).
uint32_t crc32Update(uint32_t crc, const uint8_t* data, size_t len);

inline uint32_t crc32(const uint8_t* data, size_t len) {
  return crc32Update(0, data, len);
}

}  // namespace util
