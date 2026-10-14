#pragma once
// IFileSystem over Arduino's LittleFS (the "spiffs" partition).

#include <LittleFS.h>

#include <memory>

#include "hal/file_system.h"

namespace platform {

class LittleFsFile final : public hal::IFile {
 public:
  explicit LittleFsFile(fs::File f) : f_(f) {}
  ~LittleFsFile() override { f_.close(); }
  size_t read(uint8_t* buf, size_t len) override { return f_.read(buf, len); }
  size_t write(const uint8_t* buf, size_t len) override { return f_.write(buf, len); }
  bool seek(size_t pos) override { return f_.seek(pos); }
  size_t size() const override { return const_cast<fs::File&>(f_).size(); }
  bool flush() override {
    f_.flush();
    return true;
  }

 private:
  fs::File f_;
};

class LittleFsFileSystem final : public hal::IFileSystem {
 public:
  std::unique_ptr<hal::IFile> open(const char* path, hal::FileMode mode) override {
    // Opening a missing file for reading makes LittleFS log an error; check first.
    if (mode == hal::FileMode::kRead && !LittleFS.exists(path)) return nullptr;
    fs::File f = LittleFS.open(path, mode == hal::FileMode::kRead ? "r" : "w");
    if (!f) return nullptr;
    return std::unique_ptr<hal::IFile>(new LittleFsFile(f));
  }
  bool exists(const char* path) const override { return LittleFS.exists(path); }
  bool remove(const char* path) override { return LittleFS.exists(path) && LittleFS.remove(path); }
  bool rename(const char* from, const char* to) override {
    return !LittleFS.exists(to) && LittleFS.rename(from, to);
  }
  size_t freeBytes() const override {
    const size_t total = LittleFS.totalBytes(), used = LittleFS.usedBytes();
    // Keep a margin: LittleFS needs spare blocks for metadata and wear levelling.
    const size_t margin = 64 * 1024;
    return used + margin >= total ? 0 : total - used - margin;
  }
};

}  // namespace platform
