#pragma once

#include <cstdarg>

namespace hal {

enum class LogLevel { kError = 0, kWarn = 1, kInfo = 2, kDebug = 3 };

// Logging sink. Tags are short module names: "dns", "up", "cache", "bl", "sched".
class ILogger {
 public:
  virtual ~ILogger() = default;
  virtual void vlog(LogLevel level, const char* tag, const char* fmt, va_list args) = 0;
  virtual bool enabled(LogLevel level) const = 0;

  void log(LogLevel level, const char* tag, const char* fmt, ...) __attribute__((format(printf, 4, 5))) {
    if (!enabled(level)) return;
    va_list args;
    va_start(args, fmt);
    vlog(level, tag, fmt, args);
    va_end(args);
  }
};

// Discards everything; handy default for components that log optionally.
class NullLogger final : public ILogger {
 public:
  void vlog(LogLevel, const char*, const char*, va_list) override {}
  bool enabled(LogLevel) const override { return false; }
};

}  // namespace hal
