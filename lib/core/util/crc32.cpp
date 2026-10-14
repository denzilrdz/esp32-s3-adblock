#include "util/crc32.h"

namespace util {

namespace {

struct Crc32Table {
  uint32_t entries[256];
  constexpr Crc32Table() : entries() {
    for (uint32_t i = 0; i < 256; i++) {
      uint32_t c = i;
      for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      entries[i] = c;
    }
  }
};

constexpr Crc32Table kTable;

}  // namespace

uint32_t crc32Update(uint32_t crc, const uint8_t* data, size_t len) {
  crc = ~crc;
  for (size_t i = 0; i < len; i++) crc = kTable.entries[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
  return ~crc;
}

}  // namespace util
