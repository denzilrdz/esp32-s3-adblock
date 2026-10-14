#pragma once
// IKeyValueStore over Arduino Preferences (NVS). One namespace per store.

#include <Preferences.h>

#include <cstring>

#include "hal/kv_store.h"
#include "platform/rtos.h"

namespace platform {

class NvsKvStore final : public hal::IKeyValueStore {
 public:
  explicit NvsKvStore(const char* ns) : ns_(ns) {}

  bool begin() { return prefs_.begin(ns_, false); }

  bool getString(const char* key, char* out, size_t outSize) const override {
    LockGuard g(mutex_);
    if (!prefs_.isKey(key)) return false;
    const size_t n = prefs_.getString(key, out, outSize);
    return n > 0 || (outSize > 0 && out[0] == 0);
  }
  bool setString(const char* key, const char* value) override {
    LockGuard g(mutex_);
    return prefs_.putString(key, value) == strlen(value);
  }
  bool getU32(const char* key, uint32_t& out) const override {
    LockGuard g(mutex_);
    if (!prefs_.isKey(key)) return false;
    out = prefs_.getUInt(key, 0);
    return true;
  }
  bool setU32(const char* key, uint32_t v) override {
    LockGuard g(mutex_);
    return prefs_.putUInt(key, v) == sizeof(v);
  }
  bool getI64(const char* key, int64_t& out) const override {
    LockGuard g(mutex_);
    if (!prefs_.isKey(key)) return false;
    out = prefs_.getLong64(key, 0);
    return true;
  }
  bool setI64(const char* key, int64_t v) override {
    LockGuard g(mutex_);
    return prefs_.putLong64(key, v) == sizeof(v);
  }
  bool getBlob(const char* key, uint8_t* out, size_t outSize, size_t& outLen) const override {
    LockGuard g(mutex_);
    if (!prefs_.isKey(key)) return false;
    const size_t len = prefs_.getBytesLength(key);
    if (len > outSize) return false;
    outLen = prefs_.getBytes(key, out, outSize);
    return outLen == len;
  }
  bool setBlob(const char* key, const uint8_t* data, size_t len) override {
    LockGuard g(mutex_);
    return prefs_.putBytes(key, data, len) == len;
  }
  bool erase(const char* key) override {
    LockGuard g(mutex_);
    return prefs_.remove(key);
  }

 private:
  const char* ns_;
  mutable Preferences prefs_;
  mutable Mutex mutex_;
};

}  // namespace platform
