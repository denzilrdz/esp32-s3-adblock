#include "dns/name.h"

namespace dns {

namespace {

constexpr int kMaxPointerHops = 16;

bool isLabelByte(uint8_t c) {
  return c >= 0x21 && c <= 0x7E && c != '.';
}

}  // namespace

NameParse parseUncompressedName(const uint8_t* pkt, size_t len, size_t off, uint8_t* wireOut, char* textOut) {
  NameParse r;
  size_t i = off;
  size_t wire = 0;
  size_t text = 0;
  while (true) {
    if (i >= len) return r;
    const uint8_t l = pkt[i++];
    if (l == 0) break;
    if (l > kMaxLabel) return r;  // compression pointer (0xC0) or reserved label type
    if (i + l > len) return r;
    if (wire + 1 + l + 1 > kMaxNameWire) return r;  // + this label + final root byte
    if (wireOut) wireOut[wire] = l;
    wire++;
    if (text) {
      if (textOut) textOut[text] = '.';
      text++;
    }
    for (uint8_t k = 0; k < l; k++) {
      const uint8_t c = asciiLower(pkt[i + k]);
      if (!isLabelByte(c)) return r;
      if (wireOut) wireOut[wire] = c;
      if (textOut) textOut[text] = static_cast<char>(c);
      wire++;
      text++;
    }
    i += l;
  }
  if (wireOut) wireOut[wire] = 0;
  wire++;
  if (textOut) textOut[text] = 0;
  r.ok = true;
  r.end = i;
  r.wireLen = static_cast<uint8_t>(wire);
  r.textLen = static_cast<uint8_t>(text);
  return r;
}

size_t skipName(const uint8_t* pkt, size_t len, size_t off) {
  size_t i = off;
  size_t total = 0;
  while (true) {
    if (i >= len) return 0;
    const uint8_t l = pkt[i];
    if (l == 0) return i + 1;
    if ((l & 0xC0) == 0xC0) {
      if (i + 2 > len) return 0;
      return i + 2;  // a pointer always ends the name in this byte stream
    }
    if (l & 0xC0) return 0;  // 0x40/0x80 label types are not supported
    total += 1 + l;
    if (total + 1 > kMaxNameWire) return 0;
    i += 1 + l;
  }
}

bool nameEquals(const uint8_t* pkt, size_t len, size_t off, const uint8_t* wire, size_t wireLen) {
  size_t i = off;
  size_t w = 0;
  int hops = 0;
  while (true) {
    if (i >= len || w >= wireLen) return false;
    const uint8_t l = pkt[i];
    if ((l & 0xC0) == 0xC0) {
      if (i + 2 > len || ++hops > kMaxPointerHops) return false;
      i = static_cast<size_t>(((l & 0x3F) << 8) | pkt[i + 1]);
      continue;
    }
    if (l & 0xC0) return false;
    if (wire[w] != l) return false;
    if (l == 0) return w + 1 == wireLen;
    if (i + 1 + l > len || w + 1 + l > wireLen) return false;
    for (uint8_t k = 0; k < l; k++)
      if (asciiLower(pkt[i + 1 + k]) != wire[w + 1 + k]) return false;
    i += 1 + l;
    w += 1 + l;
  }
}

}  // namespace dns
