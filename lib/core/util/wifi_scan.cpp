#include "util/wifi_scan.h"

#include <cstring>

namespace util {

size_t pickNetworks(const ScanEntry* in, size_t n, ScanEntry* out, size_t cap) {
  size_t count = 0;
  for (size_t i = 0; i < n; i++) {
    const ScanEntry& e = in[i];
    if (!e.ssid[0]) continue;  // hidden network
    size_t at = count;
    for (size_t j = 0; j < count; j++) {
      if (strcmp(out[j].ssid, e.ssid) == 0) {
        at = j;
        break;
      }
    }
    if (at < count) {
      if (e.rssi <= out[at].rssi) continue;
      // Stronger access point for a known name: drop the old entry, re-insert below.
      memmove(&out[at], &out[at + 1], (count - at - 1) * sizeof(ScanEntry));
      count--;
    }
    // Insertion point keeps the list sorted, strongest first and stable on ties.
    size_t pos = count;
    while (pos > 0 && out[pos - 1].rssi < e.rssi) pos--;
    if (pos >= cap) continue;
    const size_t keep = count < cap ? count : cap - 1;
    memmove(&out[pos + 1], &out[pos], (keep - pos) * sizeof(ScanEntry));
    out[pos] = e;
    out[pos].ssid[kMaxSsidLength] = 0;
    count = keep + 1;
  }
  return count;
}

namespace {

bool isHex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool validPassphrase(const char* p, size_t len) {
  if (len >= 8 && len <= 63) return true;
  if (len != 64) return false;
  for (size_t i = 0; i < len; i++)
    if (!isHex(p[i])) return false;
  return true;
}

}  // namespace

CredentialCheck checkCredentials(size_t ssidLength, const char* password, size_t passwordLength,
                                 WifiSecurity security) {
  if (ssidLength == 0 || ssidLength > kMaxSsidLength) return CredentialCheck::kBadName;
  switch (security) {
    case WifiSecurity::kOpen: return CredentialCheck::kOk;
    case WifiSecurity::kOther:
      if (passwordLength == 0) return CredentialCheck::kNeedPassword;
      return passwordLength <= kMaxPassphraseLength ? CredentialCheck::kOk : CredentialCheck::kBadPassword;
    case WifiSecurity::kPsk:
      if (passwordLength == 0) return CredentialCheck::kNeedPassword;
      break;
    case WifiSecurity::kUnknown:
      if (passwordLength == 0) return CredentialCheck::kOk;  // hidden open network
      break;
  }
  return validPassphrase(password, passwordLength) ? CredentialCheck::kOk : CredentialCheck::kBadPassword;
}

int signalBars(int rssi) {
  if (rssi >= -55) return 4;
  if (rssi >= -67) return 3;
  if (rssi >= -75) return 2;
  return 1;
}

}  // namespace util
