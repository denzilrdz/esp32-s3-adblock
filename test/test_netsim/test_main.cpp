// Bad-internet simulation of the daily blocklist update: the real DailyScheduler and
// BlocklistUpdater run for 90 simulated days against a network that is slow, stalls,
// drops connections, corrupts data and returns server errors, while the board's
// software watchdog (diag::LivenessMonitor) is wired as in src/platform/esp_http.cpp:
// armed for each download, checked every 5 s by "the esp_timer".
//
// The network fake models what EspHttpClient does on the device: each read gives up
// after 20 s without data, and the whole download after 5 min (kMaxDownloadUs). So it
// checks, under any mix of conditions, that:
//  - the live list is never lost, never replaced by a bad one, and no temp file stays;
//  - each day's update is retried hourly and eventually lands once the network allows;
//  - no slow-but-working download ever trips the 6 min software watchdog (5 min
//    deadline < 6 min backstop), while a download that really hangs does.

#include <unity.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "diag/liveness.h"
#include "fakes/blocklist_builder.h"
#include "fakes/fake_clock.h"
#include "fakes/fake_random.h"
#include "fakes/mem_file_system.h"
#include "fakes/mem_kv_store.h"
#include "hal/http_client.h"
#include "sched/daily_scheduler.h"
#include "update/updater.h"

namespace {

constexpr uint32_t kReadTimeoutMs = 20000;        // HttpGetRequest::timeoutMs
constexpr uint32_t kDownloadDeadlineMs = 300000;  // esp_http.cpp kMaxDownloadUs
constexpr uint32_t kDownloadStuckMs = 360000;     // main.cpp kDownloadStuckMs
constexpr uint32_t kLivenessPeriodMs = 5000;
constexpr size_t kVirtualListBytes = 1200000;  // timing as for a ~135k-domain list

class NullLogger final : public hal::ILogger {
 public:
  void vlog(hal::LogLevel, const char*, const char*, va_list) override {}
  bool enabled(hal::LogLevel) const override { return false; }
};

struct Rng {
  uint64_t s = 0x2545F4914F6CDD1Dull;
  uint32_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return static_cast<uint32_t>(s >> 11);
  }
  uint32_t below(uint32_t n) { return next() % n; }
};

enum class Net {
  kGood,         // 2 MB/s
  kSlow,         // 20-200 KB/s
  kVerySlow,     // 1-3 KB/s: can't finish inside the 5 min deadline
  kSlowOpen,     // DNS/TCP/TLS take 5-25 s, then fine
  kConnectFail,  // after 0-20 s
  kStall,        // data stops mid-body for good (read timeout)
  kReset,        // connection reset mid-body
  kCorrupt,      // a flipped byte (CRC must catch it)
  kServerError,  // 503
  kNotFound,     // 404
  kHang,         // esp_http_client never returns (only in the hang test)
};

// The server publishes a new list every day; GET honours If-None-Match.
struct Server {
  std::vector<testbl::Bytes> versions;
  size_t current = 0;
  std::string etag() const { return "\"v" + std::to_string(current) + "\""; }
};

class BadInternet final : public hal::IHttpClient {
 public:
  BadInternet(FakeClock& clock, Server& server, diag::LivenessMonitor& monitor, int id)
      : clock_(clock), server_(server), monitor_(monitor), id_(id) {}

  Net forced = Net::kGood;
  bool useForced = false;
  Rng rng;
  uint32_t calls = 0, alarms = 0;
  uint64_t longestCallMs = 0;
  std::set<std::string> alarmNames;

  hal::HttpGetResult get(const hal::HttpGetRequest& req, hal::IHttpBodySink& sink) override {
    calls++;
    monitor_.arm(id_);  // as EspHttpClient::get()
    const uint64_t start = clock_.monotonicMs();
    hal::HttpGetResult r = run(req, sink, start);
    longestCallMs = std::max(longestCallMs, clock_.monotonicMs() - start);
    monitor_.disarm(id_);
    return r;
  }

 private:
  Net pick() {
    if (useForced) return forced;
    const uint32_t roll = rng.below(100);
    if (roll < 35) return Net::kGood;
    if (roll < 55) return Net::kSlow;
    if (roll < 62) return Net::kVerySlow;
    if (roll < 72) return Net::kSlowOpen;
    if (roll < 80) return Net::kConnectFail;
    if (roll < 86) return Net::kStall;
    if (roll < 91) return Net::kReset;
    if (roll < 95) return Net::kCorrupt;
    if (roll < 98) return Net::kServerError;
    return Net::kNotFound;
  }

  // Simulated time passes in steps; the esp_timer checks the monitor meanwhile.
  bool elapse(uint64_t ms, uint64_t& lastCheck) {
    while (ms) {
      const uint64_t step = std::min<uint64_t>(ms, 1000);
      clock_.advanceMs(step);
      ms -= step;
      if (clock_.monotonicMs() - lastCheck >= kLivenessPeriodMs) {
        lastCheck = clock_.monotonicMs();
        if (const char* who = monitor_.check()) {
          alarms++;
          alarmNames.insert(who);
          return false;  // the board restarts here
        }
      }
    }
    return true;
  }

  hal::HttpGetResult run(const hal::HttpGetRequest& req, hal::IHttpBodySink& sink, uint64_t start) {
    hal::HttpGetResult r;
    uint64_t lastCheck = start;
    const Net net = pick();
    auto timedOut = [&] { return clock_.monotonicMs() - start > kDownloadDeadlineMs; };

    if (net == Net::kHang) {  // never returns on its own: only the watchdog ends it
      while (elapse(1000, lastCheck)) {
      }
      r.error = hal::HttpError::kTimeout;
      return r;
    }
    if (net == Net::kConnectFail) {
      elapse(rng.below(20000), lastCheck);
      r.error = hal::HttpError::kConnect;
      return r;
    }
    elapse(net == Net::kSlowOpen ? 5000 + rng.below(20000) : 300 + rng.below(700), lastCheck);  // open
    if (net == Net::kServerError || net == Net::kNotFound) {
      r.status = net == Net::kServerError ? 503 : 404;
      return r;
    }
    if (req.ifNoneMatch && server_.etag() == req.ifNoneMatch) {
      r.status = 304;
      return r;
    }
    testbl::Bytes body = server_.versions[server_.current];
    if (net == Net::kCorrupt) body[body.size() / 2 + rng.below(body.size() / 2)] ^= 0x5A;
    r.status = 200;
    r.contentLength = static_cast<int64_t>(body.size());
    snprintf(r.etag, sizeof(r.etag), "%s", server_.etag().c_str());

    const double bytesPerMs = net == Net::kGood       ? 2000.0
                              : net == Net::kSlow     ? 20.0 + rng.below(180)
                              : net == Net::kVerySlow ? 1.0 + rng.below(3)
                                                      : 500.0;
    const double scale = static_cast<double>(kVirtualListBytes) / body.size();
    const size_t stopAt = net == Net::kStall || net == Net::kReset ? rng.below(body.size()) : body.size();
    const size_t chunk = 1024;
    for (size_t off = 0; off < body.size(); off += chunk) {
      if (off >= stopAt) {
        if (net == Net::kStall) elapse(kReadTimeoutMs, lastCheck);  // the read times out
        r.error = net == Net::kStall ? hal::HttpError::kTimeout : hal::HttpError::kTruncated;
        return r;
      }
      const size_t n = std::min(chunk, body.size() - off);
      if (!elapse(static_cast<uint64_t>(n * scale / bytesPerMs), lastCheck)) {
        r.error = hal::HttpError::kTimeout;
        return r;
      }
      if (timedOut()) {  // esp_http.cpp: overall deadline
        r.error = hal::HttpError::kTimeout;
        return r;
      }
      if (!sink.onBodyChunk(body.data() + off, n)) {
        r.error = hal::HttpError::kAborted;
        return r;
      }
      r.bodyBytes += n;
    }
    return r;
  }

  FakeClock& clock_;
  Server& server_;
  diag::LivenessMonitor& monitor_;
  int id_;
};

class Installer final : public update::IListInstaller {
 public:
  explicit Installer(MemFileSystem& fs) : fs_(fs) {}
  bool install(const char* path, const blocklist::Header&) override {
    const testbl::Bytes* f = fs_.get(path);
    if (!f) return false;
    installed = *f;
    count++;
    return true;
  }
  testbl::Bytes installed;
  int count = 0;

 private:
  MemFileSystem& fs_;
};

blocklist::Limits limits() {
  blocklist::Limits l;
  l.minEntries = 10;
  l.maxEntries = 100000;
  return l;
}

}  // namespace

void setUp() {}
void tearDown() {}

static void test_ninety_days_of_bad_internet() {
  FakeClock clock;
  clock.setSynced(true);
  clock.setLocal(2026, 11, 1, 0, 0);
  FakeRandom random;
  MemKvStore kv;
  MemFileSystem fs(8 * 1024 * 1024);
  NullLogger log;
  diag::LivenessMonitor monitor(clock);
  const int dl = monitor.add("blocklist download", kDownloadStuckMs, false);

  Server server;
  for (int d = 0; d <= 91; d++)
    server.versions.push_back(
        testbl::build(testbl::syntheticNames(800 + d, ("d" + std::to_string(d)).c_str())));
  fs.put("/blocklist.bin", server.versions[0]);
  Installer installer(fs);
  installer.installed = server.versions[0];

  BadInternet net(clock, server, monitor, dl);
  update::BlocklistUpdater updater(limits(), fs, net, kv, installer, log);
  sched::ScheduleConfig sc;
  sc.hour = 3;
  sched::DailyScheduler scheduler(sc, clock, kv, random);

  int daysUpdated = 0, daysGaveUp = 0, attempts = 0, failures = 0;
  uint32_t maxRetriesInADay = 0;
  for (int day = 1; day <= 90; day++) {
    server.current = static_cast<size_t>(day);  // a new list every day
    net.useForced = day >= 40 && day <= 42;     // a three-day internet outage
    net.forced = Net::kConnectFail;
    bool updatedToday = false, gaveUpToday = false;
    // Follow the calendar: downloads take simulated time too, so a fixed count of
    // minutes would drift past midnight.
    const uint32_t today = clock.localTime().dateKey();
    while (clock.localTime().dateKey() == today) {
      if (scheduler.due()) {
        attempts++;
        const update::UpdateReport rep = updater.update("https://example.com/blocklist.bin");
        if (rep.success()) {
          scheduler.markSuccess();
          updatedToday = true;
        } else {
          scheduler.markFailure();
          failures++;
          gaveUpToday = gaveUpToday || scheduler.gaveUpToday();
        }
        maxRetriesInADay = std::max(maxRetriesInADay, scheduler.retriesToday());

        // After every attempt, whatever the network did:
        const testbl::Bytes* live = fs.get("/blocklist.bin");
        TEST_ASSERT_NOT_NULL(live);  // never lost
        bool known = false;
        for (const auto& v : server.versions) known = known || *live == v;
        TEST_ASSERT_TRUE_MESSAGE(known, "live list is not a published version (corrupt install)");
        TEST_ASSERT_TRUE(installer.installed == *live);  // memory matches flash
        TEST_ASSERT_FALSE(fs.exists("/blocklist.tmp"));
        TEST_ASSERT_FALSE(fs.exists("/blocklist.old"));
      }
      clock.advanceMs(60000);
    }
    if (updatedToday) {
      daysUpdated++;
      TEST_ASSERT_TRUE(*fs.get("/blocklist.bin") == server.versions[day]);
    }
    if (gaveUpToday) daysGaveUp++;
  }

  printf(
      "    90 days: %d attempts (%d failed), %d days updated, %d gave up; longest download %llu s; "
      "max retries in a day %u\n",
      attempts, failures, daysUpdated, daysGaveUp, static_cast<unsigned long long>(net.longestCallMs / 1000),
      maxRetriesInADay);
  TEST_ASSERT_EQUAL_UINT32(0, net.alarms);  // slow is never mistaken for stuck
  TEST_ASSERT_TRUE(net.longestCallMs <= kDownloadDeadlineMs + kReadTimeoutMs + 1000);
  TEST_ASSERT_TRUE(net.longestCallMs < kDownloadStuckMs);
  TEST_ASSERT_TRUE(maxRetriesInADay <= sc.maxRetries + 1);
  TEST_ASSERT_TRUE(failures > 40);     // the mix really was hostile...
  TEST_ASSERT_EQUAL(3, daysGaveUp);    // ...only the outage days gave up (7 tries each)...
  TEST_ASSERT_EQUAL(87, daysUpdated);  // ...and every other day's retries landed
}

static void test_every_condition_on_its_own() {
  // Each network condition alone: the outcome and the guarantees per condition.
  struct Case {
    Net net;
    bool expectSuccess;
  } cases[] = {{Net::kGood, true},     {Net::kSlow, true},         {Net::kVerySlow, false},
               {Net::kSlowOpen, true}, {Net::kConnectFail, false}, {Net::kStall, false},
               {Net::kReset, false},   {Net::kCorrupt, false},     {Net::kServerError, false},
               {Net::kNotFound, false}};
  for (const Case& c : cases) {
    FakeClock clock;
    MemKvStore kv;
    MemFileSystem fs(8 * 1024 * 1024);
    NullLogger log;
    diag::LivenessMonitor monitor(clock);
    const int dl = monitor.add("blocklist download", kDownloadStuckMs, false);
    Server server;
    server.versions = {testbl::build(testbl::syntheticNames(900, "a")),
                       testbl::build(testbl::syntheticNames(950, "b"))};
    server.current = 1;
    fs.put("/blocklist.bin", server.versions[0]);
    Installer installer(fs);
    BadInternet net(clock, server, monitor, dl);
    net.useForced = true;
    net.forced = c.net;
    for (int i = 0; i < 20; i++) {  // random parts (stall point, speed) vary per run
      update::BlocklistUpdater updater(limits(), fs, net, kv, installer, log);
      const update::UpdateReport rep = updater.update("https://example.com/blocklist.bin");
      TEST_ASSERT_EQUAL_MESSAGE(c.expectSuccess, rep.success(), update::updateStatusName(rep.status));
      TEST_ASSERT_TRUE(*fs.get("/blocklist.bin") == server.versions[c.expectSuccess ? 1 : 0]);
      TEST_ASSERT_FALSE(fs.exists("/blocklist.tmp"));
      if (c.expectSuccess) {  // back to the old one for the next round
        fs.put("/blocklist.bin", server.versions[0]);
        kv = MemKvStore{};
      }
    }
    TEST_ASSERT_EQUAL_UINT32(0, net.alarms);
    TEST_ASSERT_TRUE(net.longestCallMs < kDownloadStuckMs);
  }
}

static void test_a_download_that_really_hangs_is_caught() {
  FakeClock clock;
  MemKvStore kv;
  MemFileSystem fs(8 * 1024 * 1024);
  NullLogger log;
  diag::LivenessMonitor monitor(clock);
  const int dl = monitor.add("blocklist download", kDownloadStuckMs, false);
  Server server;
  server.versions = {testbl::build(testbl::syntheticNames(900, "a")),
                     testbl::build(testbl::syntheticNames(950, "b"))};
  server.current = 1;
  fs.put("/blocklist.bin", server.versions[0]);
  Installer installer(fs);
  BadInternet net(clock, server, monitor, dl);
  net.useForced = true;
  net.forced = Net::kHang;
  update::BlocklistUpdater updater(limits(), fs, net, kv, installer, log);
  updater.update("https://example.com/blocklist.bin");
  TEST_ASSERT_EQUAL_UINT32(1, net.alarms);
  TEST_ASSERT_TRUE(net.alarmNames.count("blocklist download") == 1);
  // Caught between 6 min and 6 min + one check period.
  TEST_ASSERT_TRUE(net.longestCallMs > kDownloadStuckMs);
  TEST_ASSERT_TRUE(net.longestCallMs <= kDownloadStuckMs + kLivenessPeriodMs + 1000);
  TEST_ASSERT_TRUE(*fs.get("/blocklist.bin") == server.versions[0]);  // old list kept
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_every_condition_on_its_own);
  RUN_TEST(test_a_download_that_really_hangs_is_caught);
  RUN_TEST(test_ninety_days_of_bad_internet);
  return UNITY_END();
}
