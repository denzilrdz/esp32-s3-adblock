#pragma once
// Wi-Fi setup portal helpers: the network list (one entry per name, the strongest
// access point wins, hidden networks dropped, strongest first) and the credential
// check run before anything is saved.

#include <cstddef>
#include <cstdint>

namespace util {

constexpr size_t kMaxSsidLength = 32;        // 802.11 limit, without the terminator
constexpr size_t kMaxPassphraseLength = 64;  // 63 characters, or a 64-digit hex key

enum class WifiSecurity : uint8_t {
  kOpen,     // no password (open, OWE)
  kPsk,      // WPA/WPA2/WPA3 personal: 8-63 characters or 64 hex digits
  kOther,    // WEP, enterprise, ...: any non-empty password, the router decides
  kUnknown,  // typed by hand ("Other network"): empty, or PSK rules
};

struct ScanEntry {
  char ssid[kMaxSsidLength + 1] = {};
  int rssi = 0;  // dBm
  WifiSecurity security = WifiSecurity::kPsk;
};

enum class CredentialCheck : uint8_t { kOk, kBadName, kNeedPassword, kBadPassword };

// Copies at most `cap` distinct, non-empty SSIDs from `in` into `out`, strongest
// first (ties keep scan order). Returns how many were written.
size_t pickNetworks(const ScanEntry* in, size_t n, ScanEntry* out, size_t cap);

// 1..4 signal bars: >= -55 dBm 4, >= -67 3, >= -75 2, else 1.
int signalBars(int rssi);

// Validates what the user typed before it is saved; a password for an open network
// is ignored (kOk), the caller stores it empty.
CredentialCheck checkCredentials(size_t ssidLength, const char* password, size_t passwordLength,
                                 WifiSecurity security);

}  // namespace util
