#pragma once
// Settings file: export everything a user set on the dashboard to one JSON file and
// import it again, on the same board or a new one (ARCHITECTURE.md §8.1).
//
// Included: the settings form (config.h keys, the reboot schedule too), the blocklist
// URL and update time, custom block/allow rules and banned clients. Left out on
// purpose: passwords (dashboard, OTA), Wi-Fi credentials, temporary DNS rewrites,
// statistics. A section missing from a file leaves that part of the device unchanged;
// a section that is present replaces it completely (rules and bans too).
//
// parseBackup() validates the whole file before anything is applied, so a bad file
// changes nothing.

#include <cstddef>
#include <cstdint>
#include <string>

#include "clients/ban_list.h"
#include "config/config.h"

namespace config {

constexpr const char* kBackupFormat = "esp32-s3-adblock-settings";
constexpr uint32_t kBackupVersion = 1;
constexpr size_t kMaxBackupBytes = 640 * 1024;  // 2 x 1000 rules of up to 253 characters
constexpr size_t kMaxBackupRules = 1000;        // per list (BlocklistManager::kMaxRules)
constexpr size_t kMaxBlocklistUrl = 199;        // BlocklistManager keeps it in a 200-byte buffer

struct Backup {
  bool hasSettings = false;
  AppConfig settings;

  bool hasBlocklist = false;
  std::string blocklistUrl;  // "" = the built-in default list
  uint8_t blocklistHour = 2;
  uint8_t blocklistMinute = 0;

  // Normalised domains (rules/rule_domain.h), each followed by '\n', no duplicates.
  bool hasBlockRules = false;
  std::string blockRules;
  size_t blockCount = 0;
  bool hasAllowRules = false;
  std::string allowRules;
  size_t allowCount = 0;

  bool hasBans = false;
  clients::BanList bans;

  uint32_t ignoredKeys = 0;  // unknown keys skipped (a file from newer firmware)
};

struct BackupMeta {
  const char* firmware = "";
  const char* hostname = "";
  const char* exported = "";  // local time, e.g. "2026-11-07 14:02"
};

// Appends one rule (normalised by the caller) to a Backup list.
void addRule(std::string& list, size_t& count, const char* domain);

// A blocklist URL as the dashboard and a settings file may set it: "" (the built-in
// default) or https:// with no spaces, control or non-ASCII characters, at most
// kMaxBlocklistUrl bytes. Otherwise false and *why says what is wrong.
bool validBlocklistUrl(const char* url, size_t len, const char** why);

// Writes every section of `b` (has* flags are ignored: export is always complete).
void writeBackup(const Backup& b, const BackupMeta& meta, std::string& out);

// Parses and validates `text`. Settings start from `current`, so a file with only a
// few keys changes only those. On failure `why` explains (first problem only).
bool parseBackup(const char* text, size_t len, const AppConfig& current, Backup& out, char* why,
                 size_t whyCap);

}  // namespace config
