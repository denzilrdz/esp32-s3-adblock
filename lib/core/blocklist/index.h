#pragma once
// Lookup structures for the v2 blocklist, and an RCU-style holder that lets the
// updater swap lists while DNS tasks keep reading without locks.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

#include "blocklist/format.h"
#include "hal/file_system.h"

namespace blocklist {

class IIndex {
 public:
  virtual ~IIndex() = default;
  virtual bool contains(uint64_t hash48) const = 0;
  virtual uint32_t count() const = 0;
};

// Index over the payload (bucket table + suffixes) already in memory (PSRAM on the
// S3). Does not own the memory; `owner` (optional) is destroyed with the index.
class MemoryIndex final : public IIndex {
 public:
  // `payload` points just past the header; it must stay valid for our lifetime.
  MemoryIndex(const uint8_t* payload, uint32_t count, std::shared_ptr<void> owner = nullptr)
      : table_(payload), suffixes_(payload + kBucketTableBytes), count_(count), owner_(std::move(owner)) {}
  bool contains(uint64_t hash48) const override;
  uint32_t count() const override { return count_; }

 private:
  const uint8_t* table_;
  const uint8_t* suffixes_;
  uint32_t count_;
  std::shared_ptr<void> owner_;
};

// Index read straight from the file (lite profile, no PSRAM): two small reads per
// lookup. Lookups are serialised because a file handle has one position.
class FileIndex final : public IIndex {
 public:
  FileIndex(std::unique_ptr<hal::IFile> file, uint32_t count) : file_(std::move(file)), count_(count) {}
  bool contains(uint64_t hash48) const override;
  uint32_t count() const override { return count_; }

 private:
  mutable std::mutex mutex_;
  std::unique_ptr<hal::IFile> file_;
  uint32_t count_;
};

// Holds the live index. Readers never block; publish() waits only for readers that
// are still inside the old index, then destroys it. One publisher at a time.
class IndexHolder {
 public:
  using WaitFn = void (*)();  // how the publisher waits for readers (yield/sleep)

  explicit IndexHolder(WaitFn wait = nullptr) : wait_(wait) {}

  class ReadGuard {
   public:
    ReadGuard(const IndexHolder* h, int slot) : h_(h), slot_(slot) {}
    ReadGuard(ReadGuard&& o) noexcept : h_(o.h_), slot_(o.slot_) { o.h_ = nullptr; }
    ReadGuard(const ReadGuard&) = delete;
    ReadGuard& operator=(const ReadGuard&) = delete;
    ~ReadGuard() {
      if (h_) h_->readers_[slot_].fetch_sub(1);  // seq_cst: see index.cpp
    }
    const IIndex* get() const { return h_ ? h_->slots_[slot_].get() : nullptr; }

   private:
    const IndexHolder* h_;
    int slot_;
  };

  ReadGuard acquire() const;
  // Makes `next` live, then destroys the previous index once no reader uses it.
  void publish(std::unique_ptr<IIndex> next);
  uint32_t count() const;

 private:
  WaitFn wait_;
  std::mutex writer_;
  std::unique_ptr<IIndex> slots_[2];
  std::atomic<int> current_{0};
  mutable std::atomic<uint32_t> readers_[2] = {{0}, {0}};
};

}  // namespace blocklist
