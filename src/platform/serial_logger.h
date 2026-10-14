#pragma once
// ILogger that writes "[I][tag] message" lines to the serial console. Each line is
// formatted into one buffer and written in one call, so lines from different tasks
// don't interleave.

#include <Arduino.h>

#include <cstdio>

#include "hal/logger.h"
#include "platform/rtos.h"

namespace platform {

class SerialLogger final : public hal::ILogger {
 public:
  explicit SerialLogger(hal::LogLevel level = hal::LogLevel::kInfo) : level_(level) {}

  bool enabled(hal::LogLevel level) const override { return level <= level_; }
  void setLevel(hal::LogLevel level) { level_ = level; }

  void vlog(hal::LogLevel level, const char* tag, const char* fmt, va_list args) override {
    static const char kLetters[] = {'E', 'W', 'I', 'D'};
    LockGuard g(mutex_);
    int n = snprintf(line_, sizeof(line_), "[%c][%s] ", kLetters[static_cast<int>(level)], tag);
    if (n < 0) return;
    int m = vsnprintf(line_ + n, sizeof(line_) - n - 2, fmt, args);
    if (m < 0) return;
    size_t len = static_cast<size_t>(n) + (static_cast<size_t>(m) < sizeof(line_) - n - 2 ? m : sizeof(line_) - n - 3);
    line_[len++] = '\r';
    line_[len++] = '\n';
    Serial.write(reinterpret_cast<const uint8_t*>(line_), len);
  }

 private:
  hal::LogLevel level_;
  Mutex mutex_;
  char line_[256];
};

}  // namespace platform
