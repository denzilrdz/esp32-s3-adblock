#pragma once
// In-memory IKeyValueStore. All values are stored as byte strings.

#include <cstring>
#include <map>
#include <string>

#include "hal/kv_store.h"

class MemKvStore final : public hal::IKeyValueStore {
 public:
  bool getString(const char* key, char* out, size_t outSize) const override {
    auto it = data_.find(key);
    if (it == data_.end() || it->second.size() + 1 > outSize) return false;
    memcpy(out, it->second.data(), it->second.size());
    out[it->second.size()] = 0;
    return true;
  }
  bool setString(const char* key, const char* value) override { return put(key, value); }

  bool getU32(const char* key, uint32_t& out) const override { return getPod(key, out); }
  bool setU32(const char* key, uint32_t v) override { return putPod(key, v); }
  bool getI64(const char* key, int64_t& out) const override { return getPod(key, out); }
  bool setI64(const char* key, int64_t v) override { return putPod(key, v); }

  bool getBlob(const char* key, uint8_t* out, size_t outSize, size_t& outLen) const override {
    auto it = data_.find(key);
    if (it == data_.end() || it->second.size() > outSize) return false;
    memcpy(out, it->second.data(), it->second.size());
    outLen = it->second.size();
    return true;
  }
  bool setBlob(const char* key, const uint8_t* d, size_t len) override {
    return put(key, std::string(reinterpret_cast<const char*>(d), len));
  }

  bool erase(const char* key) override { return data_.erase(key) > 0; }

  bool failWrites = false;  // simulate a full/broken NVS
  size_t writes = 0;

 private:
  bool put(const std::string& key, const std::string& value) {
    if (failWrites) return false;
    data_[key] = value;
    writes++;
    return true;
  }
  template <typename T>
  bool getPod(const char* key, T& out) const {
    auto it = data_.find(key);
    if (it == data_.end() || it->second.size() != sizeof(T)) return false;
    memcpy(&out, it->second.data(), sizeof(T));
    return true;
  }
  template <typename T>
  bool putPod(const char* key, T v) {
    return put(key, std::string(reinterpret_cast<const char*>(&v), sizeof(T)));
  }

  std::map<std::string, std::string> data_;
};
