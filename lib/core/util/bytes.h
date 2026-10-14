#pragma once
// Big/little-endian helpers and a minimal non-owning byte view (C++17 has no std::span).

#include <cstddef>
#include <cstdint>

namespace util {

inline uint16_t readU16Be(const uint8_t* p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

inline uint32_t readU32Be(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

inline void writeU16Be(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v);
}

inline void writeU32Be(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v);
}

inline uint32_t readU32Le(const uint8_t* p) {
  return p[0] | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t readU64Le(const uint8_t* p) {
  return readU32Le(p) | (static_cast<uint64_t>(readU32Le(p + 4)) << 32);
}

inline void writeU32Le(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}

inline void writeU64Le(uint8_t* p, uint64_t v) {
  writeU32Le(p, static_cast<uint32_t>(v));
  writeU32Le(p + 4, static_cast<uint32_t>(v >> 32));
}

// Non-owning view of read-only bytes.
struct ByteView {
  const uint8_t* data = nullptr;
  size_t size = 0;
};

}  // namespace util
