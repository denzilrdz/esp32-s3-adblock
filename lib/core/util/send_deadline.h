#pragma once
// Sends a large response in pieces under one overall deadline.
//
// Arduino's NetworkClient::write() retries a blocked send for ~10 s, but every byte
// that goes out resets that retry count: a client that reads a trickle at a time (one
// byte a second) would hold the single web task inside one 46 KB page send for hours.
// The dashboard sends its page through this instead (src/web/dashboard.cpp).

#include <cstddef>
#include <cstdint>

#include "hal/clock.h"

namespace util {

struct SendResult {
  size_t sent = 0;
  bool complete = false;  // false: deadline passed or write() failed; close the connection
};

// Calls write(offset, n) for consecutive pieces of at most `piece` bytes until `len`
// bytes are sent, write() returns false (connection gone) or `budgetMs` has passed
// since the start (checked before each piece, so one slow piece can overrun it by at
// most write()'s own timeout).
template <typename Write>
SendResult sendWithDeadline(size_t len, size_t piece, uint32_t budgetMs, const hal::IClock& clock,
                            Write write) {
  SendResult r;
  if (piece == 0) return r;
  const uint64_t start = clock.monotonicMs();
  while (r.sent < len) {
    if (clock.monotonicMs() - start > budgetMs) return r;
    const size_t n = len - r.sent < piece ? len - r.sent : piece;
    if (!write(r.sent, n)) return r;
    r.sent += n;
  }
  r.complete = true;
  return r;
}

}  // namespace util
