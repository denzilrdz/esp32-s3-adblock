#pragma once
// Flash file system (LittleFS on the device). Files are closed by their destructor (RAII).

#include <cstddef>
#include <cstdint>
#include <memory>

namespace hal {

class IFile {
 public:
  virtual ~IFile() = default;                         // closes the file
  virtual size_t read(uint8_t* buf, size_t len) = 0;  // bytes read; 0 at EOF/error
  virtual size_t write(const uint8_t* buf, size_t len) = 0;
  virtual bool seek(size_t pos) = 0;
  virtual size_t size() const = 0;
  virtual bool flush() = 0;
};

enum class FileMode { kRead, kWrite /* create/truncate */ };

class IFileSystem {
 public:
  virtual ~IFileSystem() = default;
  virtual std::unique_ptr<IFile> open(const char* path, FileMode mode) = 0;  // null on error
  virtual bool exists(const char* path) const = 0;
  virtual bool remove(const char* path) = 0;
  virtual bool rename(const char* from, const char* to) = 0;  // replaces nothing; `to` must not exist
  virtual size_t freeBytes() const = 0;
};

}  // namespace hal
