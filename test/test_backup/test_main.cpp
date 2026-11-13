// Tests for the settings file (lib/core/config/backup), the reboot-schedule settings
// keys in lib/core/config, and rule-domain normalisation (lib/core/rules/rule_domain).

#include <unity.h>

#include <cstring>
#include <string>

#include "config/backup.h"
#include "config/config.h"
#include "fakes/mem_kv_store.h"
#include "rules/rule_domain.h"

using config::AppConfig;
using config::Backup;
using config::SetResult;
using sched::RebootMode;

void setUp() {}
void tearDown() {}

static uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  const uint8_t bytes[4] = {a, b, c, d};
  uint32_t v;
  memcpy(&v, bytes, 4);
  return v;
}

static bool parse(const std::string& text, Backup& out, char* why = nullptr, size_t cap = 0,
                  const AppConfig& current = AppConfig{}) {
  static char sink[160];
  if (!why) why = sink, cap = sizeof(sink);
  return config::parseBackup(text.data(), text.size(), current, out, why, cap);
}

static std::string wrap(const std::string& body) {
  return "{\"format\":\"esp32-s3-adblock-settings\",\"version\":1" + (body.empty() ? "" : "," + body) + "}";
}

static void expectError(const std::string& text, const char* fragment) {
  Backup b;
  char why[160];
  TEST_ASSERT_FALSE_MESSAGE(parse(text, b, why, sizeof(why)), text.c_str());
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(why, fragment), why);
}

// ---- config: reboot keys --------------------------------------------------------

static void test_reboot_settings_keys() {
  AppConfig c;
  TEST_ASSERT_EQUAL(static_cast<int>(RebootMode::kOff), static_cast<int>(c.reboot.mode));
  TEST_ASSERT_EQUAL(SetResult::kOk, config::setField(c, "rb_mode", "weekly"));
  TEST_ASSERT_EQUAL(SetResult::kOk, config::setField(c, "rb_day", "6"));
  TEST_ASSERT_EQUAL(SetResult::kOk, config::setField(c, "rb_time", " 03:45 "));
  TEST_ASSERT_EQUAL(static_cast<int>(RebootMode::kWeekly), static_cast<int>(c.reboot.mode));
  TEST_ASSERT_EQUAL(6, c.reboot.weekday);
  TEST_ASSERT_EQUAL(3, c.reboot.hour);
  TEST_ASSERT_EQUAL(45, c.reboot.minute);
  TEST_ASSERT_EQUAL(SetResult::kInvalid, config::setField(c, "rb_mode", "hourly"));
  TEST_ASSERT_EQUAL(SetResult::kInvalid, config::setField(c, "rb_day", "7"));
  TEST_ASSERT_EQUAL(SetResult::kInvalid, config::setField(c, "rb_day", "-1"));
  TEST_ASSERT_EQUAL(SetResult::kInvalid, config::setField(c, "rb_time", "24:00"));
  TEST_ASSERT_EQUAL(SetResult::kInvalid, config::setField(c, "rb_time", "3pm"));
  TEST_ASSERT_EQUAL(6, c.reboot.weekday);  // failed sets change nothing
  TEST_ASSERT_EQUAL(3, c.reboot.hour);
  // Reboot settings apply live: no restart for them.
  AppConfig d = c;
  d.reboot.mode = RebootMode::kDaily;
  TEST_ASSERT_FALSE(config::requiresRestart(c, d));
}

static void test_reboot_settings_survive_nvs_round_trip() {
  MemKvStore kv;
  AppConfig c;
  config::setField(c, "rb_mode", "daily");
  config::setField(c, "rb_time", "23:05");
  config::setField(c, "rb_day", "2");
  TEST_ASSERT_TRUE(config::save(kv, c));
  AppConfig back;
  TEST_ASSERT_TRUE(config::load(kv, back));
  TEST_ASSERT_TRUE(back.reboot == c.reboot);
  // Settings saved by older firmware (no rb_* keys) load with the schedule off.
  MemKvStore old;
  old.setU32("cfg_ver", 1);
  old.setString("up_pri", "quad9");
  old.setString("up_sec", "cloudflare");
  AppConfig fromOld;
  TEST_ASSERT_TRUE(config::load(old, fromOld));
  TEST_ASSERT_EQUAL(static_cast<int>(RebootMode::kOff), static_cast<int>(fromOld.reboot.mode));
}

static void test_every_key_is_settable() {
  for (size_t i = 0; i < config::kKeyCount; i++) {
    AppConfig c;
    TEST_ASSERT_NOT_EQUAL_MESSAGE(static_cast<int>(SetResult::kUnknownKey),
                                  static_cast<int>(config::setField(c, config::kKeys[i], "")),
                                  config::kKeys[i]);
  }
}

// ---- rule domains ---------------------------------------------------------------

static void test_rule_domain_normalisation() {
  char out[rules::kMaxRuleDomain + 1];
  struct Case {
    const char* in;
    const char* want;  // nullptr = rejected
  } cases[] = {
      {"Ads.Example.COM", "ads.example.com"},
      {"  *.tracker.net.  ", "tracker.net"},
      {"..*.x.io", "x.io"},
      {"_dmarc.example.org", "_dmarc.example.org"},
      {"localhost", nullptr},
      {"a.b", "a.b"},
      {"ab", nullptr},
      {"a..b.com", nullptr},
      {"bad domain.com", nullptr},
      {"ex@mple.com", nullptr},
      {"*.", nullptr},
      {"", nullptr},
      {"\xC3\xA9.com", nullptr},  // IDN must be given as punycode
  };
  for (const Case& c : cases) {
    const bool ok = rules::normaliseRuleDomain(c.in, strlen(c.in), out, sizeof(out));
    TEST_ASSERT_EQUAL_MESSAGE(c.want != nullptr, ok, c.in);
    if (c.want) TEST_ASSERT_EQUAL_STRING(c.want, out);
  }
  std::string longest = std::string(249, 'a') + ".com";  // 253
  TEST_ASSERT_TRUE(rules::normaliseRuleDomain(longest.c_str(), longest.size(), out, sizeof(out)));
  longest = "a" + longest;
  TEST_ASSERT_FALSE(rules::normaliseRuleDomain(longest.c_str(), longest.size(), out, sizeof(out)));
  TEST_ASSERT_FALSE(rules::normaliseRuleDomain("a.com", 5, out, 10));  // buffer too small
}

// ---- export / import ------------------------------------------------------------

static Backup sample() {
  Backup b;
  config::setField(b.settings, "up_pri", "quad9");
  config::setField(b.settings, "up_sec", "custom");
  config::setField(b.settings, "up_cip", "94.140.14.14");
  config::setField(b.settings, "up_cname", "dns.adguard-dns.com");
  config::setField(b.settings, "pad", "0");
  config::setField(b.settings, "blk_ttl", "300");
  config::setField(b.settings, "tz", "CET-1CEST,M3.5.0,M10.5.0/3");
  config::setField(b.settings, "log", "3");
  config::setField(b.settings, "rb_mode", "weekly");
  config::setField(b.settings, "rb_day", "0");
  config::setField(b.settings, "rb_time", "04:30");
  b.blocklistUrl = "https://example.com/list.bin";
  b.blocklistHour = 3;
  b.blocklistMinute = 15;
  config::addRule(b.blockRules, b.blockCount, "ads.example.com");
  config::addRule(b.blockRules, b.blockCount, "tracker.net");
  config::addRule(b.allowRules, b.allowCount, "cdn.example.com");
  b.bans.add(ip(192, 168, 1, 50));
  b.bans.add(ip(10, 0, 0, 7));
  return b;
}

static void test_export_import_round_trip() {
  const Backup in = sample();
  config::BackupMeta meta;
  meta.firmware = "0.4.0";
  meta.hostname = "s3adblock";
  meta.exported = "2026-11-07 14:02";
  std::string text;
  config::writeBackup(in, meta, text);
  TEST_ASSERT_NOT_NULL(strstr(text.c_str(), "\"format\": \"esp32-s3-adblock-settings\""));
  TEST_ASSERT_NOT_NULL(strstr(text.c_str(), "\"pad\": false"));
  TEST_ASSERT_NOT_NULL(strstr(text.c_str(), "\"blk_ttl\": 300"));
  TEST_ASSERT_NOT_NULL(strstr(text.c_str(), "\"192.168.1.50\""));
  TEST_ASSERT_NULL(strstr(text.c_str(), "pass"));  // never any password field
  for (size_t i = 0; i < config::kKeyCount; i++) {
    const std::string key = std::string("\"") + config::kKeys[i] + "\":";
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(text.c_str(), key.c_str()), config::kKeys[i]);
  }

  Backup out;
  char why[160] = "";
  TEST_ASSERT_TRUE_MESSAGE(parse(text, out, why, sizeof(why)), why);
  TEST_ASSERT_TRUE(out.hasSettings && out.hasBlocklist && out.hasBlockRules && out.hasAllowRules &&
                   out.hasBans);
  TEST_ASSERT_EQUAL(0u, out.ignoredKeys);
  TEST_ASSERT_FALSE(config::requiresRestart(in.settings, out.settings));
  TEST_ASSERT_TRUE(in.settings.reboot == out.settings.reboot);
  TEST_ASSERT_EQUAL_STRING(in.settings.timezone, out.settings.timezone);
  TEST_ASSERT_EQUAL(in.settings.logLevel, out.settings.logLevel);
  TEST_ASSERT_EQUAL_STRING(in.blocklistUrl.c_str(), out.blocklistUrl.c_str());
  TEST_ASSERT_EQUAL(3, out.blocklistHour);
  TEST_ASSERT_EQUAL(15, out.blocklistMinute);
  TEST_ASSERT_EQUAL_STRING(in.blockRules.c_str(), out.blockRules.c_str());
  TEST_ASSERT_EQUAL(2u, out.blockCount);
  TEST_ASSERT_EQUAL_STRING(in.allowRules.c_str(), out.allowRules.c_str());
  TEST_ASSERT_EQUAL(2, out.bans.size());
  TEST_ASSERT_TRUE(out.bans.contains(ip(192, 168, 1, 50)));
  TEST_ASSERT_TRUE(out.bans.contains(ip(10, 0, 0, 7)));

  // Exporting the import gives the same file.
  std::string again;
  config::writeBackup(out, meta, again);
  TEST_ASSERT_EQUAL_STRING(text.c_str(), again.c_str());
}

static void test_export_of_defaults_and_empty_lists_round_trips() {
  Backup empty;
  std::string text;
  config::writeBackup(empty, config::BackupMeta{}, text);
  Backup out;
  char why[160] = "";
  TEST_ASSERT_TRUE_MESSAGE(parse(text, out, why, sizeof(why)), why);
  TEST_ASSERT_TRUE(out.hasBlockRules);
  TEST_ASSERT_EQUAL(0u, out.blockCount);
  TEST_ASSERT_EQUAL(0, out.bans.size());
  TEST_ASSERT_EQUAL_STRING("", out.blocklistUrl.c_str());  // "" = built-in default list
}

static void test_missing_sections_leave_the_device_unchanged() {
  AppConfig current;
  config::setField(current, "up_pri", "quad9");
  config::setField(current, "up_sec", "cloudflare");
  Backup b;
  char why[160] = "";
  TEST_ASSERT_TRUE_MESSAGE(parse(wrap("\"settings\":{\"log\":0}"), b, why, sizeof(why), current), why);
  TEST_ASSERT_TRUE(b.hasSettings);
  TEST_ASSERT_FALSE(b.hasBlocklist || b.hasBlockRules || b.hasAllowRules || b.hasBans);
  TEST_ASSERT_EQUAL(0, b.settings.logLevel);
  TEST_ASSERT_EQUAL(static_cast<int>(config::Provider::kQuad9), static_cast<int>(b.settings.primary));
  TEST_ASSERT_TRUE(parse(wrap(""), b));  // nothing at all: valid, changes nothing
  TEST_ASSERT_FALSE(b.hasSettings);
  TEST_ASSERT_TRUE(parse(wrap("\"rules\":{\"allow\":[\"a.com\"]}"), b));
  TEST_ASSERT_TRUE(b.hasAllowRules);
  TEST_ASSERT_FALSE(b.hasBlockRules);  // only the list that is present is replaced
}

static void test_settings_values_accept_text_too() {
  Backup b;
  char why[160] = "";
  TEST_ASSERT_TRUE_MESSAGE(
      parse(wrap("\"settings\":{\"pad\":\"off\",\"blk_ttl\":\" 60 \",\"rb_day\":\"3\",\"ad\":\"true\"}"), b,
            why, sizeof(why)),
      why);
  TEST_ASSERT_FALSE(b.settings.padding);
  TEST_ASSERT_EQUAL(60u, b.settings.blockedTtl);
  TEST_ASSERT_EQUAL(3, b.settings.reboot.weekday);
}

static void test_rules_are_normalised_and_deduplicated() {
  Backup b;
  char why[160] = "";
  TEST_ASSERT_TRUE_MESSAGE(
      parse(wrap("\"rules\":{\"block\":[\"Ads.Example.com\",\"*.ads.example.com\",\"x.io.\",\"x.io\"]}"), b,
            why, sizeof(why)),
      why);
  TEST_ASSERT_EQUAL_STRING("ads.example.com\nx.io\n", b.blockRules.c_str());
  TEST_ASSERT_EQUAL(2u, b.blockCount);
}

static void test_rule_and_ban_limits() {
  std::string list;
  for (size_t i = 0; i < config::kMaxBackupRules; i++) {
    if (i) list += ',';
    list += "\"d" + std::to_string(i) + ".example.com\"";
  }
  Backup b;
  char why[160] = "";
  TEST_ASSERT_TRUE_MESSAGE(parse(wrap("\"rules\":{\"block\":[" + list + "]}"), b, why, sizeof(why)), why);
  TEST_ASSERT_EQUAL(config::kMaxBackupRules, b.blockCount);
  expectError(wrap("\"rules\":{\"block\":[" + list + ",\"one-more.com\"]}"), "more than 1000");

  std::string bans;
  for (int i = 0; i < clients::BanList::kMax; i++)
    bans += (i ? "," : "") + std::string("\"10.0.0.") + std::to_string(i + 1) + "\"";
  TEST_ASSERT_TRUE(parse(wrap("\"bans\":[" + bans + "]"), b));
  TEST_ASSERT_EQUAL(clients::BanList::kMax, b.bans.size());
  TEST_ASSERT_TRUE(parse(wrap("\"bans\":[" + bans + ",\"10.0.0.1\"]"), b));  // duplicate: no extra slot
  expectError(wrap("\"bans\":[" + bans + ",\"10.0.1.1\"]"), "more than 32");
}

static void test_rejects_wrong_files_with_a_reason() {
  expectError("", "not a settings file");
  expectError("[]", "not a settings file");
  expectError("{\"version\":1}", "no \"format\"");
  expectError("{\"format\":\"other-app\",\"version\":1}", "not a settings file");
  expectError("{\"format\":7,\"version\":1}", "not a settings file");
  expectError("{\"format\":\"esp32-s3-adblock-settings\"}", "no \"version\"");
  expectError("{\"format\":\"esp32-s3-adblock-settings\",\"version\":2}", "needs newer firmware");
  expectError("{\"format\":\"esp32-s3-adblock-settings\",\"version\":0}", "version 0");
  expectError("{\"format\":\"esp32-s3-adblock-settings\",\"version\":1", "unexpected end");
  expectError(wrap("") + "x", "unexpected data");
  expectError("\xEF\xBB\xBF", "not a settings file");
  // A BOM before a valid file is fine.
  Backup b;
  TEST_ASSERT_TRUE(parse("\xEF\xBB\xBF" + wrap(""), b));
}

static void test_rejects_invalid_values_with_the_field_name() {
  expectError(wrap("\"settings\":{\"up_cip\":\"300.1.1.1\"}"), "settings.up_cip");
  expectError(wrap("\"settings\":{\"blk_ttl\":99999}"), "settings.blk_ttl");
  expectError(wrap("\"settings\":{\"blk_ttl\":-1}"), "settings");
  expectError(wrap("\"settings\":{\"blk_ttl\":1.5}"), "settings");
  expectError(wrap("\"settings\":{\"pad\":1}"), "settings.pad: wrong type");
  expectError(wrap("\"settings\":{\"tz\":true}"), "settings.tz: wrong type");
  expectError(wrap("\"settings\":{\"tz\":null}"), "settings.tz: wrong type");
  expectError(wrap("\"settings\":{\"tz\":\"UTC;reboot\"}"), "settings.tz");
  expectError(wrap("\"settings\":{\"rb_mode\":\"hourly\"}"), "settings.rb_mode");
  expectError(wrap("\"settings\":{\"rb_time\":\"25:00\"}"), "settings.rb_time");
  expectError(wrap("\"settings\":{\"up_pri\":\"none\"}"), "a primary upstream is required");
  expectError(wrap("\"settings\":{\"up_pri\":\"custom\"}"), "custom upstream needs");
  expectError(wrap("\"settings\":[]"), "settings");
  expectError(wrap("\"settings\":{\"log\":}"), "settings: unexpected character");
  expectError(wrap("\"settings\":{\"tz\":\"" + std::string(200, 'A') + "\"}"), "too long");
  expectError(wrap("\"blocklist\":{\"url\":\"http://plain.example/list.bin\"}"), "https://");
  expectError(wrap("\"blocklist\":{\"url\":\"https://a b/\"}"), "spaces");
  expectError(wrap("\"blocklist\":{\"url\":\"https://" + std::string(200, 'a') + "\"}"), "too long");
  expectError(wrap("\"blocklist\":{\"time\":\"2am\"}"), "HH:MM");
  expectError(wrap("\"blocklist\":{\"time\":200}"), "HH:MM");
  expectError(wrap("\"rules\":{\"block\":[\"not a domain\"]}"), "rules.block: invalid domain");
  expectError(wrap("\"rules\":{\"allow\":[42]}"), "rules.allow");
  expectError(wrap("\"rules\":{\"allow\":\"a.com\"}"), "rules.allow");
  expectError(wrap("\"bans\":[\"192.168.1.256\"]"), "bans: invalid IPv4");
  expectError(wrap("\"bans\":[\"fd00::1\"]"), "bans: invalid IPv4");
  expectError(wrap("\"bans\":[7]"), "bans: invalid IPv4");
  expectError(wrap("\"bans\":[\"10.0.0.1\",]"), "bans");
}

// A bad file changes nothing: the output is reset, not half-filled.
static void test_failed_parse_leaves_an_empty_result() {
  Backup b = sample();
  b.hasSettings = true;
  TEST_ASSERT_FALSE(parse(wrap("\"rules\":{\"block\":[\"ok.com\"]},\"bans\":[\"bad\"]"), b));
  TEST_ASSERT_FALSE(b.hasSettings || b.hasBlockRules || b.hasBans);
  TEST_ASSERT_EQUAL(0u, b.blockCount);
}

static void test_unknown_keys_are_skipped_and_counted() {
  Backup b;
  char why[160] = "";
  TEST_ASSERT_TRUE_MESSAGE(parse(wrap("\"future\":{\"x\":[1,2,{\"y\":null}]},\"settings\":{\"new_key\":5,"
                                      "\"log\":1},\"rules\":{\"maybe\":[]},\"blocklist\":{\"etag\":\"x\"},"
                                      "\"firmware\":\"9.9.9\",\"hostname\":\"h\",\"exported\":\"now\""),
                                 b, why, sizeof(why)),
                           why);
  TEST_ASSERT_EQUAL(4u, b.ignoredKeys);
  TEST_ASSERT_EQUAL(1, b.settings.logLevel);
}

static void test_size_limit_and_null_reason_buffer() {
  std::string big = wrap("\"pad\":\"" + std::string(config::kMaxBackupBytes, ' ') + "\"");
  Backup b;
  expectError(big, "too large");
  TEST_ASSERT_FALSE(config::parseBackup(big.data(), big.size(), AppConfig{}, b, nullptr, 0));
}

// Escapes in strings decode before validation: "\u0061ds.com" is "ads.com", and a
// control character smuggled in through an escape is still refused.
static void test_escaped_strings_are_validated_after_decoding() {
  Backup b;
  TEST_ASSERT_TRUE(parse(wrap("\"rules\":{\"block\":[\"\\u0061ds.com\"]}"), b));
  TEST_ASSERT_EQUAL_STRING("ads.com\n", b.blockRules.c_str());
  expectError(wrap("\"rules\":{\"block\":[\"ads.com\\nevil.com\"]}"), "invalid domain");
  expectError(wrap("\"blocklist\":{\"url\":\"https://x/\\r\\n\"}"), "special characters");
}

static void test_blocklist_url_rules_are_shared_with_the_dashboard() {
  // Audit 2026-11: the dashboard only checked the https:// prefix, so a longer URL was
  // saved, silently dropped at the next boot (200-byte buffer) and exported into
  // settings files that imports refused. Both now use config::validBlocklistUrl().
  const char* why = nullptr;
  TEST_ASSERT_TRUE(config::validBlocklistUrl("", 0, &why));  // the built-in default
  TEST_ASSERT_NULL(why);
  const std::string ok = "https://example.com/list.bin";
  TEST_ASSERT_TRUE(config::validBlocklistUrl(ok.c_str(), ok.size(), &why));
  const std::string longest = "https://" + std::string(config::kMaxBlocklistUrl - 8, 'a');
  TEST_ASSERT_TRUE(config::validBlocklistUrl(longest.c_str(), longest.size(), nullptr));
  const std::string tooLong = longest + "a";
  TEST_ASSERT_FALSE(config::validBlocklistUrl(tooLong.c_str(), tooLong.size(), &why));
  TEST_ASSERT_NOT_NULL(strstr(why, "too long"));
  for (const char* bad : {"http://example.com/x", "https://", "ftp://x", "https://a b/", "https://a\tb/",
                          "https://\x7f/", "https://\xc3\xa9/"}) {
    TEST_ASSERT_FALSE_MESSAGE(config::validBlocklistUrl(bad, strlen(bad), &why), bad);
    TEST_ASSERT_NOT_NULL(why);
  }
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_reboot_settings_keys);
  RUN_TEST(test_blocklist_url_rules_are_shared_with_the_dashboard);
  RUN_TEST(test_reboot_settings_survive_nvs_round_trip);
  RUN_TEST(test_every_key_is_settable);
  RUN_TEST(test_rule_domain_normalisation);
  RUN_TEST(test_export_import_round_trip);
  RUN_TEST(test_export_of_defaults_and_empty_lists_round_trips);
  RUN_TEST(test_missing_sections_leave_the_device_unchanged);
  RUN_TEST(test_settings_values_accept_text_too);
  RUN_TEST(test_rules_are_normalised_and_deduplicated);
  RUN_TEST(test_rule_and_ban_limits);
  RUN_TEST(test_rejects_wrong_files_with_a_reason);
  RUN_TEST(test_rejects_invalid_values_with_the_field_name);
  RUN_TEST(test_failed_parse_leaves_an_empty_result);
  RUN_TEST(test_unknown_keys_are_skipped_and_counted);
  RUN_TEST(test_size_limit_and_null_reason_buffer);
  RUN_TEST(test_escaped_strings_are_validated_after_decoding);
  return UNITY_END();
}
