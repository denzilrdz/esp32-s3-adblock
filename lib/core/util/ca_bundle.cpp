#include "util/ca_bundle.h"

#include <cstring>

namespace util {

namespace {

uint32_t readU32Le(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 | static_cast<uint32_t>(p[2]) << 16 |
         static_cast<uint32_t>(p[3]) << 24;
}
uint16_t readU16Le(const uint8_t* p) {
  return static_cast<uint16_t>(p[0] | p[1] << 8);
}
void writeU32Le(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}

constexpr size_t kEntryHeader = 4;  // uint16 name length + uint16 key length

// DER length at p[*i] (short or long form, up to 4 bytes). Advances *i.
bool derLength(const uint8_t* p, size_t len, size_t* i, size_t* out) {
  if (*i >= len) return false;
  const uint8_t b = p[(*i)++];
  if (b < 0x80) {
    *out = b;
    return true;
  }
  const size_t n = b & 0x7F;
  if (n == 0 || n > 4 || *i + n > len) return false;
  size_t v = 0;
  for (size_t k = 0; k < n; k++) v = v << 8 | p[(*i)++];
  *out = v;
  return true;
}

}  // namespace

namespace {

bool distrustedEntry(const uint8_t* entry, const char* const* distrusted, size_t n) {
  const uint8_t* cn = nullptr;
  size_t cnLen = 0;
  if (!subjectCommonName(entry + kEntryHeader, readU16Le(entry), &cn, &cnLen)) return false;
  for (size_t d = 0; d < n; d++)
    if (strlen(distrusted[d]) == cnLen && memcmp(distrusted[d], cn, cnLen) == 0) return true;
  return false;
}

}  // namespace

size_t caBundleCount(const uint8_t* bundle, size_t len) {
  if (!bundle || len < 4) return 0;
  const uint32_t first = readU32Le(bundle);
  if (first == 0 || first % 4 != 0 || first > len) return 0;
  return first / 4;
}

bool caBundleValid(const uint8_t* bundle, size_t len, size_t maxCerts) {
  const size_t count = caBundleCount(bundle, len);
  if (count == 0 || count > maxCerts) return false;
  size_t expected = count * 4;  // the first entry starts right after the offset list
  for (size_t i = 0; i < count; i++) {
    const uint32_t off = readU32Le(bundle + i * 4);
    if (off != expected || off + kEntryHeader > len) return false;
    const size_t entry = kEntryHeader + readU16Le(bundle + off) + readU16Le(bundle + off + 2);
    if (off + entry > len) return false;
    expected = off + entry;
  }
  return expected == len;
}

bool subjectCommonName(const uint8_t* name, size_t nameLen, const uint8_t** cn, size_t* cnLen) {
  // Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }. Scan for the encoded OID
  // 2.5.4.3 (06 03 55 04 03) followed by a string value; subjects are small and come
  // from the bundle we were built with, but every read stays bounds-checked.
  static const uint8_t kCnOid[] = {0x06, 0x03, 0x55, 0x04, 0x03};
  for (size_t i = 0; i + sizeof(kCnOid) < nameLen; i++) {
    if (memcmp(name + i, kCnOid, sizeof(kCnOid)) != 0) continue;
    size_t j = i + sizeof(kCnOid) + 1;  // skip the value's tag (UTF8String, PrintableString...)
    size_t vlen = 0;
    if (!derLength(name, nameLen, &j, &vlen) || j + vlen > nameLen) return false;
    *cn = name + j;
    *cnLen = vlen;
    return true;
  }
  return false;
}

size_t filterCaBundle(const uint8_t* in, size_t len, const char* const* distrusted, size_t distrustedCount,
                      uint8_t* out, size_t cap, size_t* removed) {
  if (removed) *removed = 0;
  const size_t count = caBundleCount(in, len);
  if (!caBundleValid(in, len, count) || cap < len) return 0;
  // Pass 1: which entries stay.
  size_t keep = 0, bodyBytes = 0;
  for (size_t i = 0; i < count; i++) {
    const uint32_t off = readU32Le(in + i * 4);
    if (distrustedEntry(in + off, distrusted, distrustedCount)) continue;
    bodyBytes += kEntryHeader + readU16Le(in + off) + readU16Le(in + off + 2);
    keep++;
  }
  if (keep == 0) return 0;  // never install an empty bundle (ESP-IDF refuses it anyway)
  // Pass 2: new offsets, then the kept entries in their original (sorted) order.
  size_t pos = keep * 4, slot = 0;
  for (size_t i = 0; i < count; i++) {
    const uint32_t off = readU32Le(in + i * 4);
    if (distrustedEntry(in + off, distrusted, distrustedCount)) continue;
    const size_t entry = kEntryHeader + readU16Le(in + off) + readU16Le(in + off + 2);
    writeU32Le(out + slot * 4, static_cast<uint32_t>(pos));
    memcpy(out + pos, in + off, entry);
    pos += entry;
    slot++;
  }
  if (removed) *removed = count - keep;
  return keep * 4 + bodyBytes;
}

}  // namespace util
