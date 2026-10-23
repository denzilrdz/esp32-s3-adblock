#pragma once
// Downloads, validates and installs a new blocklist without ever losing the old one
// (ARCHITECTURE.md §6.3):
//
//   GET (If-None-Match: last ETag) -> 304: unchanged
//   200 -> stream to /blocklist.tmp while checking header, size and CRC
//       -> full structural validation of the temp file
//       -> identical CRC to the live list: unchanged
//       -> live -> .old, tmp -> live, delete .old   (boot recovery handles a crash)
//       -> installer loads it into memory and swaps the index
//
// Any failure deletes the temp file and leaves the live list (file + memory) intact.

#include <cstddef>
#include <cstdint>

#include "blocklist/format.h"
#include "hal/file_system.h"
#include "hal/http_client.h"
#include "hal/kv_store.h"
#include "hal/logger.h"

namespace update {

struct Paths {
  const char* live = "/blocklist.bin";
  const char* tmp = "/blocklist.tmp";
  const char* old = "/blocklist.old";
};

enum class UpdateStatus {
  kUpdated,
  kUnchanged,
  kNoUrl,
  kNetworkError,
  kHttpError,
  kInvalid,
  kNoSpace,
  kFsError,
  kInstallFailed,
};

const char* updateStatusName(UpdateStatus s);

struct UpdateReport {
  UpdateStatus status = UpdateStatus::kNoUrl;
  int httpStatus = 0;
  uint32_t entries = 0;
  int64_t buildTime = 0;
  char detail[128] = {0};
  bool success() const { return status == UpdateStatus::kUpdated || status == UpdateStatus::kUnchanged; }
};

// Loads a validated list file into the live index (memory or file-backed).
class IListInstaller {
 public:
  virtual ~IListInstaller() = default;
  // Called right before the live file is renamed. An installer that serves lookups
  // straight from the live file (lite boards) must release it here, because
  // LittleFS does not support renaming/removing a file that is still open.
  virtual void prepareSwap() {}
  virtual bool install(const char* path, const blocklist::Header& header) = 0;
};

struct RecoveryResult {
  bool haveList = false;
  bool restoredOld = false;
  blocklist::Header header;
  blocklist::FormatError liveError = blocklist::FormatError::kNone;
};

class BlocklistUpdater {
 public:
  static constexpr const char* kEtagKey = "bl_etag";

  BlocklistUpdater(const blocklist::Limits& limits, hal::IFileSystem& fs, hal::IHttpClient& http,
                   hal::IKeyValueStore& kv, IListInstaller& installer, hal::ILogger& log,
                   Paths paths = Paths{});

  // Scheduled/remote update from `url` (HTTPS).
  UpdateReport update(const char* url);
  // Validates and installs a file already on flash (dashboard upload).
  UpdateReport installFile(const char* path);

  // Optional callback during long validations (feeds the task watchdog on device).
  void setProgress(blocklist::ProgressFn tick) { tick_ = tick; }

  // Boot: make sure /blocklist.bin is valid, restoring /blocklist.old after an
  // interrupted swap. Deletes stale temp files.
  static RecoveryResult recover(hal::IFileSystem& fs, const blocklist::Limits& limits, Paths paths = Paths{},
                                blocklist::ProgressFn tick = nullptr);

 private:
  UpdateReport fail(UpdateStatus s, const char* detail, int http = 0);
  UpdateReport swapAndInstall(const char* from, const blocklist::Header& h, const char* etag);
  bool liveCrc(uint32_t& crc);
  void reinstallLive();  // after a failed swap: make the live file serve lookups again

  blocklist::Limits limits_;
  hal::IFileSystem& fs_;
  hal::IHttpClient& http_;
  hal::IKeyValueStore& kv_;
  IListInstaller& installer_;
  hal::ILogger& log_;
  Paths paths_;
  blocklist::ProgressFn tick_ = nullptr;
};

}  // namespace update
