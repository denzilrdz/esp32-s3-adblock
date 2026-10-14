#include "dns/local_zones.h"

#include <cstring>

namespace dns {

namespace {

// True if `name` equals `zone` or is a subdomain of it (label boundary respected).
bool inZone(const char* name, size_t len, const char* zone) {
  const size_t z = strlen(zone);
  if (len < z || memcmp(name + len - z, zone, z) != 0) return false;
  return len == z || name[len - z - 1] == '.';
}

bool equals(const char* name, size_t len, const char* lit) {
  return strlen(lit) == len && memcmp(name, lit, len) == 0;
}

// RFC 6303 locally-served zones for private/special address space, plus mDNS.
const char* const kPrivateZones[] = {
    "10.in-addr.arpa",      "168.192.in-addr.arpa", "254.169.in-addr.arpa",
    "127.in-addr.arpa",     "0.in-addr.arpa",       "255.255.255.255.in-addr.arpa",
    "16.172.in-addr.arpa",  "17.172.in-addr.arpa",  "18.172.in-addr.arpa",
    "19.172.in-addr.arpa",  "20.172.in-addr.arpa",  "21.172.in-addr.arpa",
    "22.172.in-addr.arpa",  "23.172.in-addr.arpa",  "24.172.in-addr.arpa",
    "25.172.in-addr.arpa",  "26.172.in-addr.arpa",  "27.172.in-addr.arpa",
    "28.172.in-addr.arpa",  "29.172.in-addr.arpa",  "30.172.in-addr.arpa",
    "31.172.in-addr.arpa",  "d.f.ip6.arpa",         "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",       "a.e.f.ip6.arpa",       "b.e.f.ip6.arpa",
    "local",
};

}  // namespace

LocalAnswer classifyLocal(const char* qname, size_t len, const LocalZoneOptions& opt) {
  if (inZone(qname, len, "localhost")) return LocalAnswer::kLocalhost;
  if (opt.firefoxCanary && equals(qname, len, "use-application-dns.net")) return LocalAnswer::kNxDomain;
  if (opt.icloudPrivateRelay &&
      (equals(qname, len, "mask.icloud.com") || equals(qname, len, "mask-h2.icloud.com")))
    return LocalAnswer::kNxDomain;
  if (opt.privateReverse)
    for (const char* zone : kPrivateZones)
      if (inZone(qname, len, zone)) return LocalAnswer::kNxDomain;
  return LocalAnswer::kNone;
}

}  // namespace dns
