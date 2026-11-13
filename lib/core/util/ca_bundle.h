#pragma once
// Removing distrusted roots from ESP-IDF's TLS certificate bundle.
//
// The firmware verifies DoT/DoH upstreams and the blocklist download against the
// ESP-IDF certificate bundle compiled into the prebuilt libraries. When a root in it
// becomes untrustworthy before Espressif ships a new one, the firmware copies the
// bundle without that root at boot and installs the copy (esp_crt_bundle_set()).
// First case (2026-11, GHSA-6q48-6c7w-9gw2): eight intermediates under "emSign ECC
// Root CA - G3" had their private keys compromised, so anyone holding one could mint
// a certificate for cloudflare-dns.com or github.com.
//
// Bundle format (ESP-IDF 5.5, esp_crt_bundle.c): a list of little-endian uint32
// offsets, one per certificate (the first offset = 4 x count), then the entries in
// ascending order of their DER subject name, each: uint16 LE name length, uint16 LE
// key length, the DER subject name, the DER public key. ESP-IDF finds issuers by
// binary search over that order, so a copy must keep it.

#include <cstddef>
#include <cstdint>

namespace util {

// Roots the firmware removes from the ESP-IDF bundle at boot (exact common names).
// Add one here when a root is distrusted before the framework's bundle catches up;
// remove it once the bundle no longer ships it.
//  - "emSign ECC Root CA - G3": GHSA-6q48-6c7w-9gw2 (2026-10), eight intermediates
//    with compromised keys. The other emSign roots are unaffected.
inline constexpr const char* kDistrustedRoots[] = {"emSign ECC Root CA - G3"};
inline constexpr size_t kDistrustedRootCount = sizeof(kDistrustedRoots) / sizeof(kDistrustedRoots[0]);

// True if `bundle` is well formed: the same checks as ESP-IDF's esp_crt_check_bundle
// (offsets in order and contiguous, entries inside the buffer), at most `maxCerts`.
bool caBundleValid(const uint8_t* bundle, size_t len, size_t maxCerts);

// Number of certificates in a valid bundle (0 if invalid).
size_t caBundleCount(const uint8_t* bundle, size_t len);

// The common name (OID 2.5.4.3) in a DER subject name: points into `name`, no copy.
// False if the name has none.
bool subjectCommonName(const uint8_t* name, size_t nameLen, const uint8_t** cn, size_t* cnLen);

// Copies `in` to `out` without the certificates whose subject common name equals one
// of `distrusted` (exact match), keeping the order. Returns the size of the copy, or
// 0 if `in` is malformed or `out` too small (`cap` >= `len` is always enough).
// `*removed` (optional) receives how many certificates were dropped.
size_t filterCaBundle(const uint8_t* in, size_t len, const char* const* distrusted, size_t distrustedCount,
                      uint8_t* out, size_t cap, size_t* removed);

}  // namespace util
