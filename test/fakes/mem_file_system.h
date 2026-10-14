#pragma once
// In-memory IFileSystem with a capacity limit and fault injection.

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "hal/file_system.h"

class MemFileSystem final : public hal::IFileSystem {
 public:
  using Bytes = std::vector<uint8_t>;

  explicit MemFileSystem(size_t capacity = 8 * 1024 * 1024) : capacity_(capacity) {}

  std::unique_ptr<hal::IFile> open(const char* path, hal::FileMode mode) override {
    if (mode == hal::FileMode::kRead) {
      auto it = files_.find(path);
      if (it == files_.end()) return nullptr;
      return std::make_unique<File>(*this, it->second, false);
    }
    if (failOpenWrite) return nullptr;
    Bytes& b = files_[path];
    b.clear();
    return std::make_unique<File>(*this, b, true);
  }
  bool exists(const char* path) const override { return files_.count(path) > 0; }
  bool remove(const char* path) override { return files_.erase(path) > 0; }
  bool rename(const char* from, const char* to) override {
    if (failRename) return false;
    auto it = files_.find(from);
    if (it == files_.end() || files_.count(to)) return false;
    files_[to] = std::move(it->second);
    files_.erase(from);
    return true;
  }
  size_t freeBytes() const override {
    size_t used = 0;
    for (const auto& f : files_) used += f.second.size();
    return used >= capacity_ ? 0 : capacity_ - used;
  }

  // Test helpers.
  void put(const std::string& path, const Bytes& data) { files_[path] = data; }
  const Bytes* get(const std::string& path) const {
    auto it = files_.find(path);
    return it == files_.end() ? nullptr : &it->second;
  }

  bool failOpenWrite = false;
  bool failRename = false;

 private:
  class File final : public hal::IFile {
   public:
    File(MemFileSystem& fs, Bytes& data, bool writable) : fs_(fs), data_(data), writable_(writable) {}
    size_t read(uint8_t* buf, size_t len) override {
      size_t n = std::min(len, data_.size() - std::min(pos_, data_.size()));
      if (n) memcpy(buf, data_.data() + pos_, n);
      pos_ += n;
      return n;
    }
    size_t write(const uint8_t* buf, size_t len) override {
      if (!writable_) return 0;
      size_t n = std::min(len, fs_.freeBytes());
      data_.insert(data_.end(), buf, buf + n);
      pos_ = data_.size();
      return n;
    }
    bool seek(size_t pos) override {
      if (pos > data_.size()) return false;
      pos_ = pos;
      return true;
    }
    size_t size() const override { return data_.size(); }
    bool flush() override { return true; }

   private:
    MemFileSystem& fs_;
    Bytes& data_;
    bool writable_;
    size_t pos_ = 0;
  };

  size_t capacity_;
  std::map<std::string, Bytes> files_;
};
