#pragma once
// Owns everything blocklist-related on the device: the live index (PSRAM or
// file-backed), the matcher used by the DNS policy, custom block/allow rules, the
// 02:00 IST scheduler and the updater. loop() runs in the maintenance task.

#include <Arduino.h>

#include <vector>

#include "blocklist/index.h"
#include "blocklist/matcher.h"
#include "hal/clock.h"
#include "hal/file_system.h"
#include "hal/http_client.h"
#include "hal/kv_store.h"
#include "hal/logger.h"
#include "hal/random.h"
#include "platform/rtos.h"
#include "sched/daily_scheduler.h"
#include "update/updater.h"

namespace app {

struct BlocklistStatus {
  uint32_t entries = 0;
  int64_t buildTime = 0;
  bool inMemory = false;
  bool timeSynced = false;
  int64_t lastAttempt = 0;  // unix seconds, 0 = never
  bool lastOk = false;
  String lastResult = "never";
  uint32_t lastSuccessDate = 0;  // yyyymmdd
  uint8_t hour = 2;
  uint8_t minute = 0;
  String url;
  size_t customBlock = 0;
  size_t customAllow = 0;
};

class BlocklistManager final : public update::IListInstaller {
 public:
  static constexpr size_t kMaxRules = 1000;

  BlocklistManager(hal::IFileSystem& fs, hal::IHttpClient& http, hal::IKeyValueStore& kv,
                   const hal::IClock& clock, hal::IRandom& random, hal::ILogger& log,
                   blocklist::ProgressFn tick = nullptr);

  void begin();  // boot: recover files, load the list and custom rules
  void loop();   // maintenance task: run the daily update when due

  const blocklist::Matcher& matcher() const { return matcher_; }

  // IListInstaller
  void prepareSwap() override;
  bool install(const char* path, const blocklist::Header& header) override;

  update::UpdateReport installUpload(const char* path);
  void requestUpdate() { scheduler_.requestNow(); }
  bool setUrl(const String& url);
  void setTime(uint8_t hour, uint8_t minute);

  // Custom rules (`allow` selects the allowlist). Domains are normalised/validated.
  bool addRule(bool allow, const String& domain);
  bool removeRule(bool allow, const String& domain);
  std::vector<String> rules(bool allow);

  BlocklistStatus status();

 private:
  void loadRules();
  bool saveRules(bool allow);
  void rebuildSets();
  void record(const update::UpdateReport& r);
  static bool normalise(const String& in, String& out);

  hal::IFileSystem& fs_;
  hal::IKeyValueStore& kv_;
  const hal::IClock& clock_;
  hal::ILogger& log_;
  blocklist::ProgressFn tick_;
  blocklist::Limits limits_;
  blocklist::IndexHolder holder_;
  blocklist::Matcher matcher_;
  sched::DailyScheduler scheduler_;
  update::BlocklistUpdater updater_;
  bool inMemory_ = false;
  bool fileBacked_ = false;
  int64_t buildTime_ = 0;

  platform::Mutex updateMutex_;  // one update/upload at a time
  platform::Mutex stateMutex_;   // rules + status
  std::vector<String> block_, allow_;
  String url_;
  uint8_t hour_ = 2, minute_ = 0;
  int64_t lastAttempt_ = 0;
  bool lastOk_ = false;
  String lastResult_ = "never";
};

}  // namespace app
