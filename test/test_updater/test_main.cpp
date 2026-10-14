// Tests for lib/core/update: ETag handling, validation of downloads, the atomic
// file swap, failure paths that must keep the old list, and boot recovery.

#include <unity.h>

#include <string>
#include <vector>

#include "fakes/blocklist_builder.h"
#include "fakes/capturing_logger.h"
#include "fakes/fake_http_client.h"
#include "fakes/mem_file_system.h"
#include "fakes/mem_kv_store.h"
#include "update/updater.h"

using testbl::Bytes;
using update::BlocklistUpdater;
using update::UpdateStatus;

class RecordingInstaller final : public update::IListInstaller {
 public:
  void prepareSwap() override { prepared++; }
  bool install(const char* path, const blocklist::Header& h) override {
    calls++;
    lastPath = path;
    lastCount = h.count;
    return succeed;
  }
  int calls = 0;
  int prepared = 0;
  std::string lastPath;
  uint32_t lastCount = 0;
  bool succeed = true;
};

static const char* kUrl = "https://example.com/blocklist.bin";
static MemFileSystem* fs;
static FakeHttpClient http;
static MemKvStore kv;
static RecordingInstaller installer;
static CapturingLogger logger;
static Bytes oldList, newList;

static blocklist::Limits limits() {
  blocklist::Limits l;
  l.minEntries = 10;
  l.maxEntries = 100000;
  return l;
}

static update::UpdateReport run() {
  BlocklistUpdater u(limits(), *fs, http, kv, installer, logger);
  return u.update(kUrl);
}

void setUp() {
  delete fs;
  fs = new MemFileSystem(8 * 1024 * 1024);
  http = FakeHttpClient{};
  kv = MemKvStore{};
  installer = RecordingInstaller{};
  logger.lines.clear();
  oldList = testbl::build(testbl::syntheticNames(1000, "old"));
  newList = testbl::build(testbl::syntheticNames(1200, "new"));
  fs->put("/blocklist.bin", oldList);
}
void tearDown() {}

static void assertLiveIsOld() {
  TEST_ASSERT_NOT_NULL(fs->get("/blocklist.bin"));
  TEST_ASSERT_EQUAL(0, installer.prepared);  // failure before the swap: index untouched
  TEST_ASSERT_TRUE(*fs->get("/blocklist.bin") == oldList);
  TEST_ASSERT_FALSE(fs->exists("/blocklist.tmp"));
  TEST_ASSERT_FALSE(fs->exists("/blocklist.old"));
  TEST_ASSERT_EQUAL(0, installer.calls);
}

static void test_successful_update_swaps_file_installs_and_stores_etag() {
  http.next.body = newList;
  http.next.etag = "\"v2\"";
  const auto r = run();
  TEST_ASSERT_EQUAL_STRING("updated", update::updateStatusName(r.status));
  TEST_ASSERT_EQUAL_UINT32(1200, r.entries);
  TEST_ASSERT_TRUE(*fs->get("/blocklist.bin") == newList);
  TEST_ASSERT_FALSE(fs->exists("/blocklist.tmp"));
  TEST_ASSERT_FALSE(fs->exists("/blocklist.old"));
  TEST_ASSERT_EQUAL(1, installer.calls);
  TEST_ASSERT_EQUAL(1, installer.prepared);  // file index released before the rename
  TEST_ASSERT_EQUAL_STRING("/blocklist.bin", installer.lastPath.c_str());
  char etag[32];
  TEST_ASSERT_TRUE(kv.getString(BlocklistUpdater::kEtagKey, etag, sizeof(etag)));
  TEST_ASSERT_EQUAL_STRING("\"v2\"", etag);
}

static void test_sends_if_none_match_and_handles_304() {
  kv.setString(BlocklistUpdater::kEtagKey, "\"v1\"");
  http.next.status = 304;
  const auto r = run();
  TEST_ASSERT_EQUAL_STRING("unchanged", update::updateStatusName(r.status));
  TEST_ASSERT_TRUE(r.success());
  TEST_ASSERT_EQUAL_STRING("\"v1\"", http.requests[0].ifNoneMatch.c_str());
  assertLiveIsOld();
}

static void test_no_if_none_match_when_live_list_is_missing() {
  fs->remove("/blocklist.bin");
  kv.setString(BlocklistUpdater::kEtagKey, "\"v1\"");  // stale: file was wiped
  http.next.body = newList;
  run();
  TEST_ASSERT_EQUAL_STRING("", http.requests[0].ifNoneMatch.c_str());
  TEST_ASSERT_TRUE(*fs->get("/blocklist.bin") == newList);
}

static void test_corrupt_download_keeps_old_list() {
  Bytes bad = newList;
  bad[bad.size() / 2] ^= 0x55;  // flipped bits in transit
  http.next.body = bad;
  const auto r = run();
  TEST_ASSERT_EQUAL_STRING("invalid list", update::updateStatusName(r.status));
  TEST_ASSERT_EQUAL_STRING("crc mismatch", r.detail);
  assertLiveIsOld();
  TEST_ASSERT_EQUAL(1, logger.count(hal::LogLevel::kWarn, "keeping the current list"));
}

static void test_truncated_download_keeps_old_list() {
  http.next.body = newList;
  http.next.truncateHalf = true;
  const auto r = run();
  TEST_ASSERT_EQUAL_STRING("invalid list", update::updateStatusName(r.status));
  assertLiveIsOld();
}

static void test_wrong_file_type_is_rejected_early() {
  http.next.body = Bytes(200000, '<');  // e.g. an HTML error page served with 200
  const auto r = run();
  TEST_ASSERT_EQUAL_STRING("invalid list", update::updateStatusName(r.status));
  assertLiveIsOld();
}

static void test_network_and_http_errors_keep_old_list() {
  http.next.error = hal::HttpError::kConnect;
  TEST_ASSERT_EQUAL_STRING("network error", update::updateStatusName(run().status));
  assertLiveIsOld();
  http.next = FakeHttpClient::Response{};
  http.next.status = 404;
  const auto r = run();
  TEST_ASSERT_EQUAL_STRING("http error", update::updateStatusName(r.status));
  TEST_ASSERT_EQUAL(404, r.httpStatus);
  assertLiveIsOld();
}

static void test_list_too_big_for_flash_is_refused() {
  delete fs;
  fs = new MemFileSystem(oldList.size() + 100000);  // not enough room for old + new
  fs->put("/blocklist.bin", oldList);
  http.next.body = newList;
  const auto r = run();
  TEST_ASSERT_EQUAL_STRING("not enough flash", update::updateStatusName(r.status));
  assertLiveIsOld();
}

static void test_identical_content_without_etag_support_is_unchanged() {
  http.next.body = oldList;  // server ignores If-None-Match
  const auto r = run();
  TEST_ASSERT_EQUAL_STRING("unchanged", update::updateStatusName(r.status));
  assertLiveIsOld();
}

static void test_rename_failure_restores_old_list_and_reloads_it() {
  http.next.body = newList;
  fs->failRename = true;
  const auto r = run();
  TEST_ASSERT_EQUAL_STRING("filesystem error", update::updateStatusName(r.status));
  TEST_ASSERT_TRUE(*fs->get("/blocklist.bin") == oldList);
  // prepareSwap() released the index, so the old list must be installed again,
  // otherwise a file-backed board would stop blocking (fail-open).
  TEST_ASSERT_EQUAL(1, installer.prepared);
  TEST_ASSERT_EQUAL(1, installer.calls);
  TEST_ASSERT_EQUAL_UINT32(1000, installer.lastCount);
}

static void test_install_failure_is_reported() {
  http.next.body = newList;
  installer.succeed = false;
  const auto r = run();
  TEST_ASSERT_EQUAL_STRING("install failed", update::updateStatusName(r.status));
  TEST_ASSERT_FALSE(r.success());
  char etag[8];
  TEST_ASSERT_FALSE(kv.getString(BlocklistUpdater::kEtagKey, etag, sizeof(etag)));  // retry downloads again
}

static void test_rejects_non_https_and_empty_urls() {
  BlocklistUpdater u(limits(), *fs, http, kv, installer, logger);
  TEST_ASSERT_EQUAL_STRING("no url", update::updateStatusName(u.update("").status));
  TEST_ASSERT_EQUAL_STRING("no url", update::updateStatusName(u.update("http://example.com/x.bin").status));
  TEST_ASSERT_EQUAL(0, http.requests.size());
}

static void test_manual_upload_install_and_rejection() {
  BlocklistUpdater u(limits(), *fs, http, kv, installer, logger);
  fs->put("/upload.tmp", newList);
  TEST_ASSERT_EQUAL_STRING("updated", update::updateStatusName(u.installFile("/upload.tmp").status));
  TEST_ASSERT_TRUE(*fs->get("/blocklist.bin") == newList);
  Bytes legacy(5000, 0);  // upstream 40-bit blob: rejected
  fs->put("/upload.tmp", legacy);
  TEST_ASSERT_EQUAL_STRING("invalid list", update::updateStatusName(u.installFile("/upload.tmp").status));
  TEST_ASSERT_FALSE(fs->exists("/upload.tmp"));
  TEST_ASSERT_TRUE(*fs->get("/blocklist.bin") == newList);
}

static void test_boot_recovery_paths() {
  // (a) valid live list: stale temp/old files are cleaned up.
  fs->put("/blocklist.tmp", Bytes(10, 1));
  fs->put("/blocklist.old", oldList);
  auto r = BlocklistUpdater::recover(*fs, limits());
  TEST_ASSERT_TRUE(r.haveList);
  TEST_ASSERT_FALSE(r.restoredOld);
  TEST_ASSERT_FALSE(fs->exists("/blocklist.tmp"));
  TEST_ASSERT_FALSE(fs->exists("/blocklist.old"));
  // (b) power lost mid-swap: live corrupt, old valid -> restore old.
  Bytes half(newList.begin(), newList.begin() + newList.size() / 2);
  fs->put("/blocklist.bin", half);
  fs->put("/blocklist.old", oldList);
  r = BlocklistUpdater::recover(*fs, limits());
  TEST_ASSERT_TRUE(r.haveList);
  TEST_ASSERT_TRUE(r.restoredOld);
  TEST_ASSERT_TRUE(*fs->get("/blocklist.bin") == oldList);
  // (c) live missing, old valid -> restore.
  fs->remove("/blocklist.bin");
  fs->put("/blocklist.old", oldList);
  r = BlocklistUpdater::recover(*fs, limits());
  TEST_ASSERT_TRUE(r.restoredOld);
  // (d) nothing usable -> no list (device fails open and downloads at once).
  fs->put("/blocklist.bin", half);
  r = BlocklistUpdater::recover(*fs, limits());
  TEST_ASSERT_FALSE(r.haveList);
  TEST_ASSERT_EQUAL_STRING("size does not match entry count", blocklist::formatErrorName(r.liveError));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_successful_update_swaps_file_installs_and_stores_etag);
  RUN_TEST(test_sends_if_none_match_and_handles_304);
  RUN_TEST(test_no_if_none_match_when_live_list_is_missing);
  RUN_TEST(test_corrupt_download_keeps_old_list);
  RUN_TEST(test_truncated_download_keeps_old_list);
  RUN_TEST(test_wrong_file_type_is_rejected_early);
  RUN_TEST(test_network_and_http_errors_keep_old_list);
  RUN_TEST(test_list_too_big_for_flash_is_refused);
  RUN_TEST(test_identical_content_without_etag_support_is_unchanged);
  RUN_TEST(test_rename_failure_restores_old_list_and_reloads_it);
  RUN_TEST(test_install_failure_is_reported);
  RUN_TEST(test_rejects_non_https_and_empty_urls);
  RUN_TEST(test_manual_upload_install_and_rejection);
  RUN_TEST(test_boot_recovery_paths);
  return UNITY_END();
}
