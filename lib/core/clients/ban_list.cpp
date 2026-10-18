#include "clients/ban_list.h"

#include <cstdio>
#include <cstring>

namespace clients {

namespace {

// Parses exactly "a.b.c.d" (each 0-255, 1-3 digits) into network byte order.
bool parseIpv4(const char* s, size_t len, uint32_t& out) {
  uint8_t bytes[4];
  size_t i = 0;
  for (int part = 0; part < 4; part++) {
    unsigned v = 0;
    size_t digits = 0;
    while (i < len && s[i] >= '0' && s[i] <= '9') {
      v = v * 10 + static_cast<unsigned>(s[i++] - '0');
      if (++digits > 3 || v > 255) return false;
    }
    if (digits == 0) return false;
    bytes[part] = static_cast<uint8_t>(v);
    if (part < 3) {
      if (i >= len || s[i] != '.') return false;
      i++;
    }
  }
  if (i != len) return false;
  memcpy(&out, bytes, 4);
  return true;
}

}  // namespace

bool BanList::contains(uint32_t ip) const {
  for (int i = 0; i < count_; i++)
    if (ips_[i] == ip) return true;
  return false;
}

bool BanList::add(uint32_t ip) {
  if (contains(ip)) return true;
  if (count_ >= kMax) return false;
  ips_[count_++] = ip;
  return true;
}

bool BanList::remove(uint32_t ip) {
  for (int i = 0; i < count_; i++)
    if (ips_[i] == ip) {
      ips_[i] = ips_[--count_];
      return true;
    }
  return false;
}

void BanList::parse(const char* text, size_t len) {
  count_ = 0;
  size_t start = 0;
  while (start < len && count_ < kMax) {
    size_t end = start;
    while (end < len && text[end] != '\n') end++;
    size_t a = start, b = end;
    while (a < b && (text[a] == ' ' || text[a] == '\t' || text[a] == '\r')) a++;
    while (b > a && (text[b - 1] == ' ' || text[b - 1] == '\t' || text[b - 1] == '\r')) b--;
    uint32_t ip;
    if (b > a && parseIpv4(text + a, b - a, ip)) add(ip);
    start = end + 1;
  }
}

size_t BanList::serialize(char* out, size_t cap) const {
  size_t n = 0;
  for (int i = 0; i < count_; i++) {
    uint8_t b[4];
    memcpy(b, &ips_[i], 4);
    char line[17];
    const int len = snprintf(line, sizeof(line), "%u.%u.%u.%u\n", b[0], b[1], b[2], b[3]);
    if (len <= 0 || n + static_cast<size_t>(len) > cap) break;
    memcpy(out + n, line, static_cast<size_t>(len));
    n += static_cast<size_t>(len);
  }
  return n;
}

}  // namespace clients
