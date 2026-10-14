#pragma once
// Records formatted log lines so tests can assert on warnings (e.g. plain-DNS fallback).

#include <cstdio>
#include <string>
#include <vector>

#include "hal/logger.h"

class CapturingLogger final : public hal::ILogger {
 public:
  struct Line {
    hal::LogLevel level;
    std::string tag;
    std::string text;
  };

  void vlog(hal::LogLevel level, const char* tag, const char* fmt, va_list args) override {
    char buf[512];
    vsnprintf(buf, sizeof(buf), fmt, args);
    lines.push_back({level, tag, buf});
  }
  bool enabled(hal::LogLevel) const override { return true; }

  size_t count(hal::LogLevel level, const std::string& needle) const {
    size_t n = 0;
    for (const auto& l : lines)
      if (l.level == level && l.text.find(needle) != std::string::npos) n++;
    return n;
  }

  std::vector<Line> lines;
};
