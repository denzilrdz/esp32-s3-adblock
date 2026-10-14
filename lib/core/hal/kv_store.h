#pragma once
// Small persistent key/value store (NVS on the device). Keys are <= 15 chars (NVS limit).

#include <cstddef>
#include <cstdint>

namespace hal {

class IKeyValueStore {
 public:
  virtual ~IKeyValueStore() = default;

  // Copies the value (NUL-terminated) into out. Returns false if missing or too long.
  virtual bool getString(const char* key, char* out, size_t outSize) const = 0;
  virtual bool setString(const char* key, const char* value) = 0;

  virtual bool getU32(const char* key, uint32_t& out) const = 0;
  virtual bool setU32(const char* key, uint32_t value) = 0;

  virtual bool getI64(const char* key, int64_t& out) const = 0;
  virtual bool setI64(const char* key, int64_t value) = 0;

  // Returns the stored size via outLen. False if missing or larger than outSize.
  virtual bool getBlob(const char* key, uint8_t* out, size_t outSize, size_t& outLen) const = 0;
  virtual bool setBlob(const char* key, const uint8_t* data, size_t len) = 0;

  virtual bool erase(const char* key) = 0;
};

}  // namespace hal
