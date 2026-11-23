#pragma once
// Rolling average of recent latencies for GET /api/health (answerMsAvg, upstreamMsAvg):
// the last kSlots samples, of which only those younger than the caller's window count.
//
// Written from the DNS tasks, so record() is lock-free and allocation-free: one
// fetch_add picks the slot, two relaxed stores fill it. Several writers are fine (dns_io
// and dns_tcp share the answer ring). A reader may see a slot half-written by a
// concurrent record() (new time, old value or the reverse): one sample of 256 off by one
// query, which a rolling average tolerates. Times are 32-bit milliseconds compared by
// unsigned difference, so they survive the 49-day wrap.

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace diag {

// The window GET /api/health averages over (answerMsAvg, upstreamMsAvg).
constexpr uint32_t kAnswerWindowMs = 5 * 60 * 1000;

struct LatencyAverage {
  uint32_t samples = 0;  // samples inside the window
  double avgMs = 0;      // 0 when samples == 0
};

class LatencyRing {
 public:
  static constexpr size_t kSlots = 256;

  // `micros` is the measured latency; capped at an hour so a stuck clock can't
  // overflow the sum.
  void record(uint32_t nowMs, uint32_t micros) {
    if (micros > kMaxMicros) micros = kMaxMicros;
    Slot& s = slots_[next_.fetch_add(1, std::memory_order_relaxed) % kSlots];
    s.micros.store(micros, std::memory_order_relaxed);
    s.atMs.store(nowMs ? nowMs : 1u, std::memory_order_relaxed);  // never 0: 0 marks an empty slot
  }

  // Average of the samples recorded within the last windowMs.
  LatencyAverage average(uint32_t nowMs, uint32_t windowMs) const {
    uint64_t sumMicros = 0;
    uint32_t n = 0;
    for (const Slot& s : slots_) {
      const uint32_t at = s.atMs.load(std::memory_order_relaxed);
      if (at == 0 || nowMs - at > windowMs) continue;
      sumMicros += s.micros.load(std::memory_order_relaxed);
      n++;
    }
    LatencyAverage a;
    a.samples = n;
    if (n) a.avgMs = static_cast<double>(sumMicros) / n / 1000.0;
    return a;
  }

 private:
  static constexpr uint32_t kMaxMicros = 3600u * 1000u * 1000u;
  struct Slot {
    std::atomic<uint32_t> atMs{0};
    std::atomic<uint32_t> micros{0};
  };
  Slot slots_[kSlots];
  std::atomic<uint32_t> next_{0};
};

}  // namespace diag
