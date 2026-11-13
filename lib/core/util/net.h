#pragma once
// IPv4 address classification for the DNS server's "LAN only" rule.

#include <cstdint>

namespace util {

// True for RFC 1918 (10/8, 172.16/12, 192.168/16), loopback (127/8) and link-local
// (169.254/16) addresses. `ip` is in host byte order (ntohl of sin_addr). The DNS
// service answers only these, so the board never becomes an open resolver if port 53
// is ever exposed to the internet (port forwarding, a DMZ host, a bridged modem).
inline bool isPrivateIpv4(uint32_t ip) {
  return (ip >> 24) == 10 || (ip >> 20) == (172u << 4 | 1) || (ip >> 16) == (192u << 8 | 168) ||
         (ip >> 24) == 127 || (ip >> 16) == (169u << 8 | 254);
}

}  // namespace util
