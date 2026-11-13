#include "app/blocklist_manager.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <memory>

#include "config/backup.h"
#include "platform/psram.h"
#include "rules/rule_domain.h"

namespace app {

using hal::LogLevel;

namespace {

constexpr const char* kTag = "bl";
constexpr const char* kLivePath = "/blocklist.bin";
constexpr const char* kBlockRules = "/custom.txt";
constexpr const char* kAllowRules = "/allow.txt";
constexpr const char* kKeyUrl = "bl_url";
constexpr const char* kKeyHour = "bl_hour";
constexpr const char* kKeyMinute = "bl_min";
constexpr const char* kKeyResult = "bl_res";
constexpr const char* kKeyOk = "bl_ok";  // kept with bl_res: a restart showed "updated" as failed
constexpr const char* kKeyAttempt = "bl_at";

#ifndef DEFAULT_BLOCKLIST_URL
#define DEFAULT_BLOCKLIST_URL \
  "https://github.com/denzilrdz/esp32-s3-adblock/releases/download/blocklist/blocklist.bin"
#endif

void yieldBriefly() {
  vTaskDelay(1);
}

}  // namespace

BlocklistManager::BlocklistManager(hal::IFileSystem& fs, hal::IHttpClient& http, hal::IKeyValueStore& kv,
                                   const hal::IClock& clock, hal::IRandom& random, hal::ILogger& log,
                                   blocklist::ProgressFn tick)
    : fs_(fs),
      kv_(kv),
      clock_(clock),
      log_(log),
      tick_(tick),
      limits_([] {
        blocklist::Limits l;
        l.maxEntries = 1000000;  // ~4.3 MB in PSRAM; live + temp copies fit the 7.9 MB LittleFS
        return l;
      }()),
      holder_(yieldBriefly),
      matcher_(holder_),
      scheduler_(sched::ScheduleConfig{}, clock, kv, random),
      updater_(limits_, fs, http, kv, *this, log) {
  updater_.setProgress(tick);
}

void BlocklistManager::begin() {
  char buf[200];
  url_ = kv_.getString(kKeyUrl, buf, sizeof(buf)) ? String(buf) : String(DEFAULT_BLOCKLIST_URL);
  uint32_t v;
  if (kv_.getU32(kKeyHour, v) && v < 24) hour_ = static_cast<uint8_t>(v);
  if (kv_.getU32(kKeyMinute, v) && v < 60) minute_ = static_cast<uint8_t>(v);
  scheduler_.setTime(hour_, minute_);
  if (kv_.getString(kKeyResult, buf, sizeof(buf))) lastResult_ = buf;
  kv_.getI64(kKeyAttempt, lastAttempt_);
  uint32_t ok = 0;
  if (kv_.getU32(kKeyOk, ok)) lastOk_ = ok != 0;
  fs_.remove("/update.cfg");  // upstream's settings file: superseded by NVS

  const update::RecoveryResult rec = update::BlocklistUpdater::recover(fs_, limits_, update::Paths{}, tick_);
  if (rec.restoredOld) log_.log(LogLevel::kWarn, kTag, "restored previous list after an interrupted update");
  if (rec.haveList) {
    install(kLivePath, rec.header);
  } else {
    log_.log(LogLevel::kWarn, kTag, "no valid blocklist (%s): blocking only custom rules until the download",
             blocklist::formatErrorName(rec.liveError));
    scheduler_.requestNow();  // fetch as soon as the network is up
  }
  loadRules();
}

void BlocklistManager::prepareSwap() {
  // A file-backed index (the PSRAM-short bridge) keeps the live file open; LittleFS
  // can't rename it while open, so drop it. Only custom rules block during the swap.
  if (fileBacked_) {
    holder_.publish(nullptr);
    fileBacked_ = false;
  }
}

bool BlocklistManager::install(const char* path, const blocklist::Header& h) {
  const size_t size = blocklist::fileSizeFor(h.count);
  void* mem = platform::allocLarge(size);
  if (!mem) {
    // Not enough PSRAM for old + new side by side: bridge through a file-backed index
    // so blocking never stops, free the old list, then load into memory.
    auto f = fs_.open(path, hal::FileMode::kRead);
    if (!f) return false;
    holder_.publish(std::unique_ptr<blocklist::IIndex>(new blocklist::FileIndex(std::move(f), h.count)));
    fileBacked_ = true;
    inMemory_ = false;
    buildTime_ = h.buildTime;
    mem = platform::allocLarge(size);
    if (!mem) {
      log_.log(LogLevel::kWarn, kTag, "PSRAM exhausted: serving the list from flash");
      return true;
    }
  }
  std::shared_ptr<void> owner(mem, platform::LargeFree());
  auto f = fs_.open(path, hal::FileMode::kRead);
  uint8_t* p = static_cast<uint8_t*>(mem);
  size_t got = 0, n;
  while (f && got < size && (n = f->read(p + got, size - got > 4096 ? 4096 : size - got)) > 0) {
    got += n;
    if (tick_ && (got & 0xFFFF) < 4096) tick_();  // ~every 64 KB
  }
  if (got != size) {
    log_.log(LogLevel::kError, kTag, "short read loading the list (%u of %u bytes)",
             static_cast<unsigned>(got), static_cast<unsigned>(size));
    return fileBacked_;  // keep whatever is live
  }
  holder_.publish(std::unique_ptr<blocklist::IIndex>(
      new blocklist::MemoryIndex(p + blocklist::kHeaderSize, h.count, std::move(owner))));
  fileBacked_ = false;
  inMemory_ = true;
  buildTime_ = h.buildTime;
  log_.log(LogLevel::kInfo, kTag, "loaded %u domains into PSRAM (%u KB)", static_cast<unsigned>(h.count),
           static_cast<unsigned>(size / 1024));
  return true;
}

void BlocklistManager::record(const update::UpdateReport& r) {
  platform::LockGuard g(stateMutex_);
  lastAttempt_ = clock_.wallClockSynced() ? clock_.unixTime() : 0;
  lastOk_ = r.success();
  lastResult_ =
      String(update::updateStatusName(r.status)) + (r.detail[0] ? String(": ") + r.detail : String());
  kv_.setString(kKeyResult, lastResult_.c_str());
  kv_.setI64(kKeyAttempt, lastAttempt_);
  kv_.setU32(kKeyOk, lastOk_ ? 1 : 0);
}

void BlocklistManager::loop() {
  if (!scheduler_.due()) return;
  String url;
  {
    platform::LockGuard g(stateMutex_);
    url = url_;
  }
  log_.log(LogLevel::kInfo, kTag, "updating blocklist from %s", url.c_str());
  update::UpdateReport r;
  {
    platform::LockGuard g(updateMutex_);
    r = updater_.update(url.c_str());
  }
  record(r);
  if (r.success())
    scheduler_.markSuccess();
  else
    scheduler_.markFailure();
}

update::UpdateReport BlocklistManager::installUpload(const char* path) {
  update::UpdateReport r;
  {
    platform::LockGuard g(updateMutex_);
    r = updater_.installFile(path);
  }
  record(r);
  return r;
}

const char* BlocklistManager::defaultUrl() {
  return DEFAULT_BLOCKLIST_URL;
}

bool BlocklistManager::setUrl(const String& url) {
  // Same rules as a settings import: an unchecked long URL worked until the next boot
  // (begin() reads it into 200 bytes) and made exports that imports refuse.
  if (!config::validBlocklistUrl(url.c_str(), url.length(), nullptr)) return false;
  platform::LockGuard g(stateMutex_);
  const String next = url.length() ? url : String(DEFAULT_BLOCKLIST_URL);
  if (next != url_) kv_.erase(update::BlocklistUpdater::kEtagKey);  // that ETag is for the old list
  url_ = next;
  kv_.setString(kKeyUrl, url_.c_str());
  return true;
}

void BlocklistManager::setTime(uint8_t hour, uint8_t minute) {
  if (hour > 23 || minute > 59) return;
  platform::LockGuard g(stateMutex_);
  hour_ = hour;
  minute_ = minute;
  kv_.setU32(kKeyHour, hour);
  kv_.setU32(kKeyMinute, minute);
  scheduler_.setTime(hour, minute);
}

bool BlocklistManager::normalise(const String& in, String& out) {
  char buf[rules::kMaxRuleDomain + 1];
  if (!rules::normaliseRuleDomain(in.c_str(), in.length(), buf, sizeof(buf))) return false;
  out = buf;
  return true;
}

void BlocklistManager::loadRules() {
  platform::LockGuard g(stateMutex_);
  for (int pass = 0; pass < 2; pass++) {
    std::vector<String>& list = pass ? allow_ : block_;
    list.clear();
    auto f = fs_.open(pass ? kAllowRules : kBlockRules, hal::FileMode::kRead);
    if (!f) continue;
    String line, norm;
    uint8_t c;
    while (f->read(&c, 1) == 1) {
      if (c != '\n') {
        line += static_cast<char>(c);
        continue;
      }
      if (normalise(line, norm) && list.size() < kMaxRules) list.push_back(norm);
      line = "";
    }
    if (normalise(line, norm) && list.size() < kMaxRules) list.push_back(norm);
  }
  rebuildSets();
}

bool BlocklistManager::saveRules(bool allow) {
  const std::vector<String>& list = allow ? allow_ : block_;
  auto f = fs_.open(allow ? kAllowRules : kBlockRules, hal::FileMode::kWrite);
  if (!f) return false;
  for (const String& d : list) {
    f->write(reinterpret_cast<const uint8_t*>(d.c_str()), d.length());
    f->write(reinterpret_cast<const uint8_t*>("\n"), 1);
  }
  return true;
}

void BlocklistManager::rebuildSets() {
  blocklist::DomainSet block, allow;
  for (const String& d : block_) block.add(d.c_str(), d.length());
  for (const String& d : allow_) allow.add(d.c_str(), d.length());
  block.finalize();
  allow.finalize();
  matcher_.setCustom(std::move(block), std::move(allow));
}

bool BlocklistManager::addRule(bool allow, const String& domain) {
  String d;
  if (!normalise(domain, d)) return false;
  platform::LockGuard g(stateMutex_);
  std::vector<String>& list = allow ? allow_ : block_;
  for (const String& x : list)
    if (x == d) return true;
  if (list.size() >= kMaxRules) return false;
  list.push_back(d);
  saveRules(allow);
  rebuildSets();
  return true;
}

bool BlocklistManager::removeRule(bool allow, const String& domain) {
  String d;
  if (!normalise(domain, d)) return false;
  platform::LockGuard g(stateMutex_);
  std::vector<String>& list = allow ? allow_ : block_;
  for (size_t i = 0; i < list.size(); i++) {
    if (list[i] == d) {
      list.erase(list.begin() + static_cast<long>(i));
      saveRules(allow);
      rebuildSets();
      return true;
    }
  }
  return false;
}

bool BlocklistManager::replaceRules(bool allow, const std::string& lines) {
  std::vector<String> next;
  String d;
  size_t start = 0;
  while (start < lines.size()) {
    size_t nl = lines.find('\n', start);
    if (nl == std::string::npos) nl = lines.size();
    if (normalise(String(lines.substr(start, nl - start).c_str()), d) && next.size() < kMaxRules)
      next.push_back(d);
    start = nl + 1;
  }
  platform::LockGuard g(stateMutex_);
  (allow ? allow_ : block_).swap(next);
  const bool saved = saveRules(allow);
  rebuildSets();
  return saved;
}

std::vector<String> BlocklistManager::rules(bool allow) {
  platform::LockGuard g(stateMutex_);
  return allow ? allow_ : block_;
}

BlocklistStatus BlocklistManager::status() {
  BlocklistStatus s;
  s.entries = holder_.count();
  s.inMemory = inMemory_;
  s.timeSynced = scheduler_.timeValid();
  s.lastSuccessDate = scheduler_.lastSuccessDate();
  platform::LockGuard g(stateMutex_);
  s.buildTime = buildTime_;
  s.lastAttempt = lastAttempt_;
  s.lastOk = lastOk_;
  s.lastResult = lastResult_;
  s.hour = hour_;
  s.minute = minute_;
  s.url = url_;
  s.customBlock = block_.size();
  s.customAllow = allow_.size();
  return s;
}

}  // namespace app
