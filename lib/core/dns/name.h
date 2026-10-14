#pragma once
// Domain-name wire-format helpers. All functions are bounds-checked against the
// packet length and never read past it.

#include <cstddef>
#include <cstdint>

namespace dns {

constexpr size_t kMaxNameWire = 255;  // including the root label
constexpr size_t kMaxNameText = 253;  // dotted text without the trailing dot
constexpr size_t kMaxLabel = 63;

struct NameParse {
  bool ok = false;
  size_t end = 0;       // offset just past the name
  uint8_t wireLen = 0;  // bytes written to wireOut (incl. root 0)
  uint8_t textLen = 0;  // chars written to textOut (excl. NUL)
};

// Parses an UNCOMPRESSED name at pkt[off] (the question section must not use
// compression). Labels may only contain printable ASCII (0x21..0x7E) other than '.'.
// Writes the lowercased wire form into wireOut (>= kMaxNameWire bytes) and the
// lowercased dotted text into textOut (>= kMaxNameText + 1 bytes); either may be null.
// The root name yields wireLen 1 and an empty text.
NameParse parseUncompressedName(const uint8_t* pkt, size_t len, size_t off, uint8_t* wireOut, char* textOut);

// Skips a possibly compressed name at pkt[off]. Returns the offset just past it in
// the original byte stream, or 0 if the name is malformed or runs past len.
size_t skipName(const uint8_t* pkt, size_t len, size_t off);

// Compares a possibly compressed name at pkt[off] with an uncompressed lowercase wire
// name, ignoring ASCII case. Pointer chains are followed with a hop limit.
bool nameEquals(const uint8_t* pkt, size_t len, size_t off, const uint8_t* wire, size_t wireLen);

inline uint8_t asciiLower(uint8_t c) {
  return (c >= 'A' && c <= 'Z') ? static_cast<uint8_t>(c + ('a' - 'A')) : c;
}

}  // namespace dns
