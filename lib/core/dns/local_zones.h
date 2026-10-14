#pragma once
// Names answered locally so they never leak upstream (ARCHITECTURE.md §5.5).

#include <cstddef>

namespace dns {

enum class LocalAnswer {
  kNone,       // not local: continue with blocklist / upstream
  kLocalhost,  // 127.0.0.1 / ::1
  kNxDomain,   // answer NXDOMAIN locally
};

struct LocalZoneOptions {
  bool firefoxCanary = true;        // use-application-dns.net -> NXDOMAIN (disables Firefox DoH)
  bool icloudPrivateRelay = false;  // mask(-h2).icloud.com -> NXDOMAIN (disables Private Relay)
  bool privateReverse = true;       // RFC 6303 reverse zones, .local -> NXDOMAIN
};

// `qname` is lowercase dotted text without a trailing dot (dns::Query::qname).
LocalAnswer classifyLocal(const char* qname, size_t len, const LocalZoneOptions& opt);

}  // namespace dns
