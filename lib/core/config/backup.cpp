#include "config/backup.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "rules/rewrites.h"
#include "rules/rule_domain.h"
#include "util/civil_time.h"
#include "util/json.h"

namespace config {

namespace {

enum class Kind { kText, kBool, kNumber };

Kind kindOf(const char* key) {
  static const char* const bools[] = {"up_doh", "up_plain",  "up_cdoh", "pad",
                                      "ad",     "ff_canary", "icloud",  "priv_rev"};
  static const char* const numbers[] = {"blk_ttl", "log", "rb_day"};
  for (const char* k : bools)
    if (!strcmp(k, key)) return Kind::kBool;
  for (const char* k : numbers)
    if (!strcmp(k, key)) return Kind::kNumber;
  return Kind::kText;
}

bool isKey(const char* key) {
  for (size_t i = 0; i < kKeyCount; i++)
    if (!strcmp(kKeys[i], key)) return true;
  return false;
}

// Current value of a settings key as text (the form setField() accepts).
bool fieldText(const AppConfig& c, const char* key, char* out, size_t cap) {
  auto put = [&](const char* s) { return static_cast<size_t>(snprintf(out, cap, "%s", s)) < cap; };
  auto num = [&](unsigned v) { return static_cast<size_t>(snprintf(out, cap, "%u", v)) < cap; };
  if (!strcmp(key, "up_pri")) return put(providerName(c.primary));
  if (!strcmp(key, "up_sec")) return put(providerName(c.secondary));
  if (!strcmp(key, "up_doh")) return num(c.dohFallback);
  if (!strcmp(key, "up_plain")) return num(c.plainFallback);
  if (!strcmp(key, "up_cip")) return put(c.customIp);
  if (!strcmp(key, "up_cip2")) return put(c.customIp2);
  if (!strcmp(key, "up_cname")) return put(c.customName);
  if (!strcmp(key, "up_cdoh")) return num(c.customDoh);
  if (!strcmp(key, "pad")) return num(c.padding);
  if (!strcmp(key, "ad")) return num(c.passAd);
  if (!strcmp(key, "blk_ttl")) return num(c.blockedTtl);
  if (!strcmp(key, "ff_canary")) return num(c.firefoxCanary);
  if (!strcmp(key, "icloud")) return num(c.icloudRelay);
  if (!strcmp(key, "priv_rev")) return num(c.privateReverse);
  if (!strcmp(key, "tz")) return put(c.timezone);
  if (!strcmp(key, "log")) return num(c.logLevel);
  if (!strcmp(key, "rb_mode")) return put(sched::rebootModeName(c.reboot.mode));
  if (!strcmp(key, "rb_day")) return num(c.reboot.weekday);
  if (!strcmp(key, "rb_time")) {
    return static_cast<size_t>(snprintf(out, cap, "%02u:%02u", c.reboot.hour % 24u, c.reboot.minute % 60u)) <
           cap;
  }
  return false;
}

void hhmm(char (&out)[6], uint8_t h, uint8_t m) {
  snprintf(out, sizeof(out), "%02u:%02u", h % 24u, m % 60u);
}

void writeRules(util::JsonWriter& w, const std::string& list) {
  w.beginArray();
  size_t start = 0;
  while (start < list.size()) {
    size_t nl = list.find('\n', start);
    if (nl == std::string::npos) nl = list.size();
    if (nl > start) w.value(list.data() + start, nl - start);
    start = nl + 1;
  }
  w.endArray();
}

class Parser {
 public:
  Parser(const char* text, size_t len, char* why, size_t cap) : r_(text, len), why_(why), cap_(cap) {}

  bool run(const AppConfig& current, Backup& b) {
    b = Backup{};
    b.settings = current;
    if (!r_.beginObject()) return say("not a settings file (expected a JSON object)");
    bool sawFormat = false, sawVersion = false;
    char key[32];
    while (r_.nextKey(key, sizeof(key))) {
      bool ok;
      ctx_ = key;
      if (!strcmp(key, "format")) {
        char f[48];
        if (r_.peek() != util::JsonReader::Type::kString || !r_.readString(f, sizeof(f)) ||
            strcmp(f, kBackupFormat) != 0)
          return say("not a settings file from this ad blocker");
        ok = sawFormat = true;
      } else if (!strcmp(key, "version")) {
        uint32_t v = 0;
        ok = r_.readU32(v);
        if (ok && (v < 1 || v > kBackupVersion))
          return say("settings file version %lu needs newer firmware", static_cast<unsigned long>(v));
        sawVersion = true;
      } else if (!strcmp(key, "settings")) {
        ok = settings(b);
      } else if (!strcmp(key, "blocklist")) {
        ok = blocklist(b);
      } else if (!strcmp(key, "rules")) {
        ok = rules(b);
      } else if (!strcmp(key, "bans")) {
        ok = bans(b);
      } else if (!strcmp(key, "firmware") || !strcmp(key, "hostname") || !strcmp(key, "exported")) {
        ok = r_.skipValue();  // informational only
      } else {
        b.ignoredKeys++;
        ok = r_.skipValue();
      }
      if (!ok) return failed();
    }
    ctx_ = nullptr;
    if (!r_.ok() || !r_.atEnd()) return failed();
    if (!sawFormat) return say("not a settings file from this ad blocker (no \"format\")");
    if (!sawVersion) return say("settings file has no \"version\"");
    if (b.hasSettings) {
      const char* why = nullptr;
      if (!validate(b.settings, &why)) return say("settings: %s", why);
    }
    return true;
  }

 private:
  __attribute__((format(printf, 2, 3))) bool say(const char* fmt, ...) {
    if (!message_) {
      va_list ap;
      va_start(ap, fmt);
      vsnprintf(why_, cap_, fmt, ap);
      va_end(ap);
      message_ = true;
    }
    return false;
  }
  // A reader error, with the section it happened in.
  bool failed() {
    if (message_) return false;
    const unsigned long at = static_cast<unsigned long>(r_.errorOffset());
    return ctx_ ? say("%s: %s (byte %lu)", ctx_, r_.error(), at)
                : say("not valid JSON: %s (byte %lu)", r_.error(), at);
  }

  bool settings(Backup& b) {
    if (!r_.beginObject()) return false;
    b.hasSettings = true;
    char key[24], text[128];
    while (r_.nextKey(key, sizeof(key))) {
      const Kind kind = kindOf(key);
      const util::JsonReader::Type t = r_.peek();
      bool ok = true;
      if (!isKey(key)) {
        b.ignoredKeys++;
        if (!r_.skipValue()) return false;
        continue;
      }
      if (t == util::JsonReader::Type::kString) {
        ok = r_.readString(text, sizeof(text));
      } else if (t == util::JsonReader::Type::kBool && kind == Kind::kBool) {
        bool v = false;
        ok = r_.readBool(v);
        snprintf(text, sizeof(text), "%d", v ? 1 : 0);
      } else if (t == util::JsonReader::Type::kNumber && kind == Kind::kNumber) {
        uint32_t v = 0;
        ok = r_.readU32(v);
        snprintf(text, sizeof(text), "%lu", static_cast<unsigned long>(v));
      } else if (t == util::JsonReader::Type::kNone) {
        return r_.skipValue();  // reports the syntax error
      } else {
        return say("settings.%s: wrong type of value", key);
      }
      if (!ok) return false;
      if (setField(b.settings, key, text) != SetResult::kOk)
        return say("settings.%s: invalid value \"%s\"", key, text);
    }
    return r_.ok();
  }

  bool blocklist(Backup& b) {
    if (!r_.beginObject()) return false;
    b.hasBlocklist = true;
    char key[16];
    while (r_.nextKey(key, sizeof(key))) {
      if (!strcmp(key, "url")) {
        char url[kMaxBlocklistUrl + 1];
        size_t n = 0;
        if (!r_.readString(url, sizeof(url), &n)) return false;
        const char* bad = nullptr;
        if (!validBlocklistUrl(url, n, &bad)) return say("%s", bad);
        b.blocklistUrl.assign(url, n);
      } else if (!strcmp(key, "time")) {
        char t[8];
        if (r_.peek() != util::JsonReader::Type::kString || !r_.readString(t, sizeof(t)))
          return say("blocklist.time must be HH:MM");
        if (!util::parseHhMm(t, b.blocklistHour, b.blocklistMinute))
          return say("blocklist.time must be HH:MM");
      } else {
        b.ignoredKeys++;
        if (!r_.skipValue()) return false;
      }
    }
    return r_.ok();
  }

  bool ruleList(const char* name, std::string& list, size_t& count) {
    if (!r_.beginArray()) return false;
    list.clear();
    count = 0;
    char raw[300], norm[rules::kMaxRuleDomain + 1];
    while (r_.nextElement()) {
      size_t n = 0;
      if (!r_.readString(raw, sizeof(raw), &n)) return false;
      if (!rules::normaliseRuleDomain(raw, n, norm, sizeof(norm)))
        return say("rules.%s: invalid domain \"%.60s\"", name, raw);
      // Duplicates collapse (the dashboard never stores one twice).
      const size_t len = strlen(norm);
      bool dup = false;
      for (size_t pos = 0; pos < list.size() && !dup;) {
        const size_t nl = list.find('\n', pos);
        dup = nl - pos == len && list.compare(pos, len, norm) == 0;
        pos = nl + 1;
      }
      if (dup) continue;
      if (count >= kMaxBackupRules)
        return say("rules.%s: more than %u domains", name, static_cast<unsigned>(kMaxBackupRules));
      addRule(list, count, norm);
    }
    return r_.ok();
  }

  bool rules(Backup& b) {
    if (!r_.beginObject()) return false;
    char key[16];
    while (r_.nextKey(key, sizeof(key))) {
      if (!strcmp(key, "block")) {
        ctx_ = "rules.block";
        b.hasBlockRules = true;
        if (!ruleList("block", b.blockRules, b.blockCount)) return false;
      } else if (!strcmp(key, "allow")) {
        ctx_ = "rules.allow";
        b.hasAllowRules = true;
        if (!ruleList("allow", b.allowRules, b.allowCount)) return false;
      } else {
        b.ignoredKeys++;
        if (!r_.skipValue()) return false;
      }
    }
    return r_.ok();
  }

  bool bans(Backup& b) {
    if (!r_.beginArray()) return false;
    b.hasBans = true;
    b.bans = clients::BanList{};
    char ip[20];
    while (r_.nextElement()) {
      size_t n = 0;
      uint8_t a[4];
      if (r_.peek() != util::JsonReader::Type::kString || !r_.readString(ip, sizeof(ip), &n))
        return say("bans: invalid IPv4 address");
      if (!rules::parseIpv4Strict(ip, n, a)) return say("bans: invalid IPv4 address \"%s\"", ip);
      uint32_t v;
      memcpy(&v, a, 4);  // network byte order, like lwIP
      if (!b.bans.add(v)) return say("bans: more than %d addresses", clients::BanList::kMax);
    }
    return r_.ok();
  }

  util::JsonReader r_;
  char* why_;
  size_t cap_;
  bool message_ = false;
  const char* ctx_ = nullptr;  // top-level key being read (points into run()'s buffer)
};

}  // namespace

void addRule(std::string& list, size_t& count, const char* domain) {
  list += domain;
  list += '\n';
  count++;
}

void writeBackup(const Backup& b, const BackupMeta& meta, std::string& out) {
  util::JsonWriter w(out);
  w.beginObject();
  w.key("format");
  w.value(kBackupFormat);
  w.key("version");
  w.value(kBackupVersion);
  w.key("firmware");
  w.value(meta.firmware);
  w.key("hostname");
  w.value(meta.hostname);
  w.key("exported");
  w.value(meta.exported);

  w.key("settings");
  w.beginObject();
  char text[128];
  for (size_t i = 0; i < kKeyCount; i++) {
    const char* k = kKeys[i];
    if (!fieldText(b.settings, k, text, sizeof(text))) continue;
    w.key(k);
    switch (kindOf(k)) {
      case Kind::kBool: w.value(strcmp(text, "0") != 0); break;
      case Kind::kNumber: w.value(static_cast<uint32_t>(strtoul(text, nullptr, 10))); break;
      case Kind::kText: w.value(text); break;
    }
  }
  w.endObject();

  w.key("blocklist");
  w.beginObject();
  w.key("url");
  w.value(b.blocklistUrl.c_str());
  char t[6];
  hhmm(t, b.blocklistHour, b.blocklistMinute);
  w.key("time");
  w.value(t);
  w.endObject();

  w.key("rules");
  w.beginObject();
  w.key("block");
  writeRules(w, b.blockRules);
  w.key("allow");
  writeRules(w, b.allowRules);
  w.endObject();

  w.key("bans");
  w.beginArray();
  for (int i = 0; i < b.bans.size(); i++) {
    const uint32_t v = b.bans.at(i);
    uint8_t a[4];
    memcpy(a, &v, 4);
    char ip[16];
    snprintf(ip, sizeof(ip), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    w.value(ip);
  }
  w.endArray();
  w.endObject();
  out += '\n';
}

bool validBlocklistUrl(const char* url, size_t len, const char** why) {
  const char* reason = nullptr;
  if (len > kMaxBlocklistUrl)
    reason = "blocklist.url is too long (max 199 characters)";
  else if (len && (len < 9 || strncmp(url, "https://", 8) != 0))
    reason = "blocklist.url must start with https://";
  for (size_t i = 0; !reason && i < len; i++)
    if (static_cast<unsigned char>(url[i]) <= 0x20 || static_cast<unsigned char>(url[i]) >= 0x7f)
      reason = "blocklist.url: spaces or special characters are not allowed";
  if (why) *why = reason;
  return !reason;
}

bool parseBackup(const char* text, size_t len, const AppConfig& current, Backup& out, char* why,
                 size_t whyCap) {
  char dummy[4];
  if (!why || !whyCap) why = dummy, whyCap = sizeof(dummy);
  why[0] = 0;
  if (len > kMaxBackupBytes) {
    snprintf(why, whyCap, "file too large (over %u KB)", static_cast<unsigned>(kMaxBackupBytes / 1024));
    return false;
  }
  // A UTF-8 byte order mark (some editors add one) is not JSON.
  if (len >= 3 && memcmp(text, "\xEF\xBB\xBF", 3) == 0) text += 3, len -= 3;
  Parser p(text, len, why, whyCap);
  if (p.run(current, out)) return true;
  out = Backup{};
  return false;
}

}  // namespace config
