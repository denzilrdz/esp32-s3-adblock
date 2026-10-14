#include "update/updater.h"

#include <cstdio>
#include <cstring>
#include <memory>

#include "util/bytes.h"

namespace update {

using hal::LogLevel;
using blocklist::FormatError;

namespace {

constexpr const char* kTag = "bl";

// Writes the body to the temp file while validating it on the fly.
class DownloadSink final : public hal::IHttpBodySink {
 public:
  DownloadSink(hal::IFileSystem& fs, const char* path, const blocklist::Limits& limits)
      : fs_(fs), path_(path), validator_(limits) {}

  bool onBodyChunk(const uint8_t* data, size_t len) override {
    if (!file_) {
      file_ = fs_.open(path_, hal::FileMode::kWrite);
      if (!file_) {
        fsError = true;
        return false;
      }
    }
    validator_.feed(data, len);
    received_ += len;
    if (validator_.earlyError() != FormatError::kNone) return false;
    // As soon as the header is in, refuse lists that cannot fit in flash.
    if (validator_.headerSeen() && !sizeChecked_) {
      sizeChecked_ = true;
      if (blocklist::fileSizeFor(validator_.header().count) > fs_.freeBytes() + received_) {
        noSpace = true;
        return false;
      }
    }
    if (file_->write(data, len) != len) {
      noSpace = true;
      return false;
    }
    return true;
  }

  FormatError finish() {
    if (file_) {
      file_->flush();
      file_.reset();  // close before validating/renaming
    }
    return validator_.finish();
  }
  const blocklist::Header& header() const { return validator_.header(); }

  bool noSpace = false;
  bool fsError = false;

 private:
  hal::IFileSystem& fs_;
  const char* path_;
  blocklist::StreamValidator validator_;
  std::unique_ptr<hal::IFile> file_;
  size_t received_ = 0;
  bool sizeChecked_ = false;
};

}  // namespace

const char* updateStatusName(UpdateStatus s) {
  switch (s) {
    case UpdateStatus::kUpdated: return "updated";
    case UpdateStatus::kUnchanged: return "unchanged";
    case UpdateStatus::kNoUrl: return "no url";
    case UpdateStatus::kNetworkError: return "network error";
    case UpdateStatus::kHttpError: return "http error";
    case UpdateStatus::kInvalid: return "invalid list";
    case UpdateStatus::kNoSpace: return "not enough flash";
    case UpdateStatus::kFsError: return "filesystem error";
    case UpdateStatus::kInstallFailed: return "install failed";
  }
  return "?";
}

BlocklistUpdater::BlocklistUpdater(const blocklist::Limits& limits, hal::IFileSystem& fs, hal::IHttpClient& http,
                                   hal::IKeyValueStore& kv, IListInstaller& installer, hal::ILogger& log, Paths paths)
    : limits_(limits), fs_(fs), http_(http), kv_(kv), installer_(installer), log_(log), paths_(paths) {}

UpdateReport BlocklistUpdater::fail(UpdateStatus s, const char* detail, int http) {
  fs_.remove(paths_.tmp);
  UpdateReport r;
  r.status = s;
  r.httpStatus = http;
  snprintf(r.detail, sizeof(r.detail), "%s", detail ? detail : "");
  log_.log(LogLevel::kWarn, kTag, "update failed: %s (%s); keeping the current list", updateStatusName(s), r.detail);
  return r;
}

bool BlocklistUpdater::liveCrc(uint32_t& crc) {
  auto f = fs_.open(paths_.live, hal::FileMode::kRead);
  uint8_t head[blocklist::kHeaderSize];
  blocklist::Header h;
  if (!f || f->read(head, sizeof(head)) != sizeof(head) ||
      blocklist::parseHeader(head, sizeof(head), h) != FormatError::kNone)
    return false;
  crc = h.crc;
  return true;
}

UpdateReport BlocklistUpdater::update(const char* url) {
  if (!url || !*url) return fail(UpdateStatus::kNoUrl, "no list URL configured");
  if (strncmp(url, "https://", 8) != 0) return fail(UpdateStatus::kNoUrl, "URL must be https://");

  char etag[96] = {0};
  size_t etagLen = 0;
  const bool haveLive = fs_.exists(paths_.live);
  if (haveLive) kv_.getString(kEtagKey, etag, sizeof(etag));
  etagLen = strlen(etag);

  fs_.remove(paths_.tmp);
  DownloadSink sink(fs_, paths_.tmp, limits_);
  hal::HttpGetRequest req;
  req.url = url;
  req.ifNoneMatch = etagLen ? etag : nullptr;
  const hal::HttpGetResult res = http_.get(req, sink);
  const FormatError fe = sink.finish();

  if (res.error == hal::HttpError::kConnect || res.error == hal::HttpError::kTimeout)
    return fail(UpdateStatus::kNetworkError, res.error == hal::HttpError::kTimeout ? "timeout" : "connect failed");
  if (res.status == 304) {
    fs_.remove(paths_.tmp);
    UpdateReport r;
    r.status = UpdateStatus::kUnchanged;
    r.httpStatus = 304;
    snprintf(r.detail, sizeof(r.detail), "not modified");
    log_.log(LogLevel::kInfo, kTag, "list unchanged (304)");
    return r;
  }
  if (res.status != 200) {
    char d[32];
    snprintf(d, sizeof(d), "HTTP %d", res.status);
    return fail(UpdateStatus::kHttpError, d, res.status);
  }
  if (sink.noSpace) return fail(UpdateStatus::kNoSpace, "list larger than free flash", 200);
  if (sink.fsError) return fail(UpdateStatus::kFsError, "cannot write temp file", 200);
  if (res.error == hal::HttpError::kTruncated) return fail(UpdateStatus::kInvalid, "download truncated", 200);
  if (fe != FormatError::kNone) return fail(UpdateStatus::kInvalid, blocklist::formatErrorName(fe), 200);
  if (res.error != hal::HttpError::kNone) return fail(UpdateStatus::kInvalid, "download aborted", 200);

  blocklist::Header h;
  const FormatError full = blocklist::validateFile(fs_, paths_.tmp, limits_, &h, tick_);
  if (full != FormatError::kNone) return fail(UpdateStatus::kInvalid, blocklist::formatErrorName(full), 200);

  uint32_t current = 0;
  if (haveLive && liveCrc(current) && current == h.crc) {
    fs_.remove(paths_.tmp);
    if (res.etag[0]) kv_.setString(kEtagKey, res.etag);
    UpdateReport r;
    r.status = UpdateStatus::kUnchanged;
    r.httpStatus = 200;
    r.entries = h.count;
    r.buildTime = h.buildTime;
    snprintf(r.detail, sizeof(r.detail), "same content");
    log_.log(LogLevel::kInfo, kTag, "list unchanged (same CRC)");
    return r;
  }
  return swapAndInstall(paths_.tmp, h, res.etag);
}

UpdateReport BlocklistUpdater::installFile(const char* path) {
  blocklist::Header h;
  const FormatError e = blocklist::validateFile(fs_, path, limits_, &h, tick_);
  if (e != FormatError::kNone) {
    fs_.remove(path);
    UpdateReport r;
    r.status = UpdateStatus::kInvalid;
    snprintf(r.detail, sizeof(r.detail), "%s", blocklist::formatErrorName(e));
    return r;
  }
  return swapAndInstall(path, h, nullptr);
}

UpdateReport BlocklistUpdater::swapAndInstall(const char* from, const blocklist::Header& h, const char* etag) {
  // live -> old, new -> live, delete old. A crash in between is repaired by recover().
  // prepareSwap() may have released the live index (file-backed lite boards), so
  // every failure below must reinstall the list that is live on disk afterwards.
  installer_.prepareSwap();
  fs_.remove(paths_.old);
  const bool hadLive = fs_.exists(paths_.live);
  if (hadLive && !fs_.rename(paths_.live, paths_.old)) {
    reinstallLive();
    return fail(UpdateStatus::kFsError, "rename live->old");
  }
  if (!fs_.rename(from, paths_.live)) {
    if (hadLive) fs_.rename(paths_.old, paths_.live);  // put the old list back
    fs_.remove(from);
    reinstallLive();
    return fail(UpdateStatus::kFsError, "rename new->live");
  }
  fs_.remove(paths_.old);

  UpdateReport r;
  r.entries = h.count;
  r.buildTime = h.buildTime;
  r.httpStatus = etag ? 200 : 0;
  if (!installer_.install(paths_.live, h)) {
    r.status = UpdateStatus::kInstallFailed;
    snprintf(r.detail, sizeof(r.detail), "saved, but could not load (reboot to apply)");
    log_.log(LogLevel::kError, kTag, "new list saved but not loaded");
    return r;
  }
  if (etag && etag[0]) kv_.setString(kEtagKey, etag);
  else if (!etag) kv_.erase(kEtagKey);  // manual upload: next download must be full
  r.status = UpdateStatus::kUpdated;
  snprintf(r.detail, sizeof(r.detail), "%u domains", static_cast<unsigned>(h.count));
  log_.log(LogLevel::kInfo, kTag, "blocklist updated: %u domains", static_cast<unsigned>(h.count));
  return r;
}

void BlocklistUpdater::reinstallLive() {
  blocklist::Header h;
  if (blocklist::validateFile(fs_, paths_.live, limits_, &h, tick_) == FormatError::kNone && installer_.install(paths_.live, h))
    return;
  log_.log(LogLevel::kError, kTag, "could not reload the previous list after a failed swap");
}

RecoveryResult BlocklistUpdater::recover(hal::IFileSystem& fs, const blocklist::Limits& limits, Paths paths,
                                          blocklist::ProgressFn tick) {
  RecoveryResult r;
  fs.remove(paths.tmp);
  if (fs.exists(paths.live)) {
    r.liveError = blocklist::validateFile(fs, paths.live, limits, &r.header, tick);
    if (r.liveError == FormatError::kNone) {
      fs.remove(paths.old);
      r.haveList = true;
      return r;
    }
  } else {
    r.liveError = FormatError::kIoError;
  }
  blocklist::Header oldHeader;
  if (fs.exists(paths.old) && blocklist::validateFile(fs, paths.old, limits, &oldHeader, tick) == FormatError::kNone) {
    fs.remove(paths.live);
    if (fs.rename(paths.old, paths.live)) {
      r.haveList = true;
      r.restoredOld = true;
      r.header = oldHeader;
    }
    return r;
  }
  fs.remove(paths.old);
  return r;
}

}  // namespace update
