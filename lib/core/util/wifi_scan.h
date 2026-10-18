#pragma once
// Wi-Fi scan results for the setup portal's network list: one entry per name (the
// strongest access point wins), hidden networks dropped, strongest first.

#include <cstddef>
#include <cstdint>

namespace util {

constexpr size_t kMaxSsidLength = 32;  // 802.11 limit, without the terminator

struct ScanEntry {
  char ssid[kMaxSsidLength + 1] = {};
  int rssi = 0;  // dBm
  bool secured = false;
};

// Copies at most `cap` distinct, non-empty SSIDs from `in` into `out`, strongest
// first (ties keep scan order). Returns how many were written.
size_t pickNetworks(const ScanEntry* in, size_t n, ScanEntry* out, size_t cap);

// 1..4 signal bars: >= -55 dBm 4, >= -67 3, >= -75 2, else 1.
int signalBars(int rssi);

}  // namespace util
