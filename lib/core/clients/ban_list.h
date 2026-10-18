#pragma once
// Banned client IPs, persisted as /banned.txt (one dotted IPv4 per line). The list is
// the only source of truth: a ban stays until it is lifted, whether or not the client
// has been seen since boot or is still in the client table.
//
// IPs are 32-bit IPv4 in network byte order, as lwIP and Arduino's IPAddress store
// them (first octet in the first byte in memory).

#include <cstddef>
#include <cstdint>

namespace clients {

class BanList {
 public:
  static constexpr int kMax = 32;
  // Enough for kMax lines of "255.255.255.255\n".
  static constexpr size_t kMaxTextBytes = kMax * 16;

  bool contains(uint32_t ip) const;
  // False only when the list is full and `ip` isn't in it yet.
  bool add(uint32_t ip);
  bool remove(uint32_t ip);
  int size() const { return count_; }
  uint32_t at(int i) const { return ips_[i]; }

  // Replaces the list with the IPs in `text`. Blank, malformed and duplicate lines are
  // skipped; stops at kMax entries.
  void parse(const char* text, size_t len);
  // Writes whole lines only; returns the bytes written (no terminating NUL).
  size_t serialize(char* out, size_t cap) const;

 private:
  uint32_t ips_[kMax] = {0};
  int count_ = 0;
};

}  // namespace clients
