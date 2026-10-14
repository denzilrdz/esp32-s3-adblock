#include "web/dashboard.h"

#include <LittleFS.h>
#include <Update.h>
#include <WiFi.h>
#include <mbedtls/base64.h>

#include <ctime>

#include "web/page.h"
#include "web/portal.h"

namespace web {

using hal::LogLevel;

namespace {

constexpr const char* kTag = "web";
constexpr const char* kCsrfHeader = "X-Requested-With";
constexpr const char* kCsrfValue = "adblock";
constexpr const char* kUploadTmp = "/upload.tmp";

String jsonEscape(const String& s) {
  String o;
  o.reserve(s.length() + 2);
  for (char c : s) {
    switch (c) {
      case '"': o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n"; break;
      case '\r': o += "\\r"; break;
      case '\t': o += "\\t"; break;
      default:
        if (static_cast<uint8_t>(c) < 0x20) {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", c);
          o += buf;
        } else {
          o += c;
        }
    }
  }
  return o;
}

String q(const String& s) {
  return "\"" + jsonEscape(s) + "\"";
}
const char* b(bool v) {
  return v ? "true" : "false";
}

String macString(const uint8_t* m) {
  char s[18];
  snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
  return s;
}

String formatTime(int64_t unix) {
  if (unix <= 0) return "never";
  const time_t t = static_cast<time_t>(unix);
  struct tm tmv;
  localtime_r(&t, &tmv);
  char buf[24];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tmv);
  return buf;
}

// Parses "Authorization: Basic base64(user:pass)".
bool parseBasicAuth(const String& header, String& user, String& pass) {
  if (!header.startsWith("Basic ")) return false;
  const String enc = header.substring(6);
  unsigned char out[192];
  size_t len = 0;
  if (enc.length() > 250 ||
      mbedtls_base64_decode(out, sizeof(out) - 1, &len, reinterpret_cast<const unsigned char*>(enc.c_str()),
                            enc.length()) != 0)
    return false;
  out[len] = 0;
  const char* colon = strchr(reinterpret_cast<const char*>(out), ':');
  if (!colon) return false;
  user = String(reinterpret_cast<const char*>(out)).substring(0, colon - reinterpret_cast<const char*>(out));
  pass = String(colon + 1);
  return true;
}

}  // namespace

void Dashboard::sendText(int code, const String& text) {
  ctx_.server->send(code, "text/plain", text);
}

Dashboard::Check Dashboard::check(Access access) {
  WebServer& s = *ctx_.server;
  const String ip = WiFi.localIP().toString();
  if (!auth::hostAllowed(s.header("Host").c_str(), ip.c_str(), ctx_.hostname))
    return {false, 403, "unknown Host header (use the device IP or its .local name)", false};
  if (access == Access::kPublic) return {true, 200, "", false};
  if (s.method() != HTTP_POST) return {false, 405, "use POST", false};
  if (s.header(kCsrfHeader) != kCsrfValue) return {false, 403, "missing X-Requested-With header", false};
  if (!auth::originAllowed(s.header("Origin").c_str(), s.header("Referer").c_str(), ip.c_str(),
                           ctx_.hostname))
    return {false, 403, "cross-site request refused", false};
  const uint32_t client = static_cast<uint32_t>(s.client().remoteIP());
  if (!ctx_.logins->allowed(client)) return {false, 429, "too many failed logins; try again later", false};
  String user, pass;
  if (!parseBasicAuth(s.header("Authorization"), user, pass) ||
      !ctx_.passwords->verify(user.c_str(), pass.c_str())) {
    if (s.header("Authorization").length()) {
      ctx_.logins->onFailure(client);
      ctx_.log->log(LogLevel::kWarn, kTag, "failed login from %s", s.client().remoteIP().toString().c_str());
      // Global brute-force brake without a lockout anyone could trigger: the single
      // web task spends a fixed second per failure (on top of PBKDF2), capping
      // guesses at ~1/s in total however many addresses an attacker uses.
      delay(1000);
    }
    return {false, 401, "login required", true};
  }
  ctx_.logins->onSuccess(client);
  if (ctx_.passwords->mustChange() && access != Access::kAuthDuringSetup)
    return {false, 403, "set a dashboard password first", false};
  return {true, 200, "", false};
}

bool Dashboard::guard(Access access) {
  const Check c = check(access);
  if (c.ok) return true;
  if (c.askCredentials) {
    ctx_.server->requestAuthentication(BASIC_AUTH, "adblock", c.message);
    return false;
  }
  if (c.code == 429) {
    const uint32_t client = static_cast<uint32_t>(ctx_.server->client().remoteIP());
    ctx_.server->sendHeader("Retry-After", String(ctx_.logins->retryAfterSeconds(client)));
  }
  sendText(c.code, c.message);
  return false;
}

void Dashboard::begin() {
  WebServer& s = *ctx_.server;
  const char* headers[] = {"Host", "Origin", "Referer", kCsrfHeader};
  s.collectHeaders(headers, sizeof(headers) / sizeof(headers[0]));  // Authorization is always kept

  s.on("/", HTTP_GET, [this]() {
    if (!guard(Access::kPublic)) return;
    ctx_.server->sendHeader("Content-Security-Policy",
                            "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                            "frame-ancestors 'none'");
    ctx_.server->sendHeader("X-Frame-Options", "DENY");
    ctx_.server->send_P(200, "text/html", kPage);
  });
  s.on("/api/stats", HTTP_GET, [this]() { handleStats(); });
  s.on("/api/config", HTTP_GET, [this]() { handleGetConfig(); });
  s.on("/api/config", HTTP_POST, [this]() { handleSetConfig(); });
  s.on("/api/login", HTTP_POST, [this]() {
    if (guard(Access::kAuthDuringSetup)) sendText(200, ctx_.passwords->mustChange() ? "setup" : "ok");
  });
  s.on("/api/password", HTTP_POST, [this]() { handlePassword(); });
  s.on("/api/rules/add", HTTP_POST, [this]() { handleRule(true); });
  s.on("/api/rules/remove", HTTP_POST, [this]() { handleRule(false); });
  s.on("/api/clients/ban", HTTP_POST, [this]() { handleBan(); });
  s.on("/api/blocking/pause", HTTP_POST, [this]() { handlePause(); });
  s.on("/api/blocking/resume", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    ctx_.clients->resume();
    sendText(200, "blocking resumed");
  });
  s.on("/api/blocklist/settings", HTTP_POST, [this]() { handleBlocklistSettings(); });
  s.on("/api/blocklist/update", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    ctx_.blocklist->requestUpdate();
    sendText(200, "update queued; result appears under Blocklist");
  });
  s.on("/api/cache/flush", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    ctx_.dns->flushCache();
    sendText(200, "cache flushed");
  });
  s.on("/api/wifi/forget", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    sendText(200, "Wi-Fi forgotten; rebooting into the setup portal");
    forgetWifi();
    delay(500);
    ESP.restart();
  });
  s.on("/api/reboot", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    sendText(200, "rebooting");
    delay(500);
    ESP.restart();
  });
  s.on(
      "/api/blocklist/upload", HTTP_POST, [this]() { handleListUploadDone(); },
      [this]() { handleListUpload(); });
  s.on(
      "/api/firmware", HTTP_POST, [this]() { handleFirmwareUploadDone(); },
      [this]() { handleFirmwareUpload(); });
  s.onNotFound([this]() {
    if (guard(Access::kPublic)) sendText(404, "not found");
  });
}

void Dashboard::handleStats() {
  if (!guard(Access::kPublic)) return;
  const uint32_t up = millis() / 1000;
  char uptime[24];
  snprintf(uptime, sizeof(uptime), "%lud %luh %lum", static_cast<unsigned long>(up / 86400),
           static_cast<unsigned long>((up % 86400) / 3600), static_cast<unsigned long>((up % 3600) / 60));
  const app::BlocklistStatus bl = ctx_.blocklist->status();
  const app::DnsStats d = ctx_.dns->stats();
  const cache::CacheStats cs = ctx_.dns->cacheStats();
  const app::UpstreamSnapshot us = ctx_.dns->upstreams();
  char hhmm[6];
  snprintf(hhmm, sizeof(hhmm), "%02u:%02u", bl.hour, bl.minute);

  String j;
  j.reserve(4096);
  j += "{\"version\":" + q(ctx_.version) + ",\"hostname\":" + q(ctx_.hostname);
  j += ",\"ip\":" + q(WiFi.localIP().toString()) + ",\"rssi\":" + String(WiFi.RSSI());
  j += ",\"uptime\":" + q(uptime) + ",\"heap\":" + String(ESP.getFreeHeap()) +
       ",\"heapMin\":" + String(ESP.getMinFreeHeap()) + ",\"psram\":" + String(ESP.getFreePsram()) +
       ",\"temp\":" + String(temperatureRead(), 1);
  j += ",\"setupRequired\":" + String(b(ctx_.passwords->mustChange()));
  j += ",\"timeSynced\":" + String(b(bl.timeSynced)) + ",\"now\":" + q(formatTime(time(nullptr)));
  j += ",\"blocking\":" + String(b(ctx_.clients->blockingOn())) +
       ",\"resumeIn\":" + String(ctx_.clients->resumeInSeconds());
  j += ",\"dns\":{\"queries\":" + String(d.queries) + ",\"tcp\":" + String(d.tcpQueries) +
       ",\"blocked\":" + String(d.blocked) + ",\"local\":" + String(d.local) +
       ",\"cacheHits\":" + String(d.cacheHits) + ",\"forwarded\":" + String(d.forwarded) +
       ",\"servfail\":" + String(d.servfail) + ",\"cacheEntries\":" + String(cs.entries) + "}";
  j += ",\"plainFallback\":" + String(b(us.plainFallback)) + ",\"upstreams\":[";
  for (size_t i = 0; i < us.count; i++) {
    const upstream::UpstreamStatus& u = us.status[i];
    if (i) j += ",";
    j += "{\"name\":" + q(u.name) + ",\"encrypted\":" + b(u.authenticated) +
         ",\"state\":" + q(upstream::healthStateName(u.state)) + ",\"ok\":" + String(u.stats.ok) +
         ",\"failed\":" + String(u.stats.failed) + ",\"latencyMs\":" + String(u.stats.lastLatencyMs) + "}";
  }
  j += "],\"blocklist\":{\"entries\":" + String(bl.entries) + ",\"inMemory\":" + b(bl.inMemory) +
       ",\"built\":" + q(formatTime(bl.buildTime)) + ",\"lastAttempt\":" + q(formatTime(bl.lastAttempt)) +
       ",\"lastOk\":" + b(bl.lastOk) + ",\"lastResult\":" + q(bl.lastResult) + ",\"url\":" + q(bl.url) +
       ",\"time\":" + q(hhmm) + "}";
  j += ",\"rules\":{\"block\":[";
  const auto block = ctx_.blocklist->rules(false);
  for (size_t i = 0; i < block.size(); i++) j += (i ? "," : "") + q(block[i]);
  j += "],\"allow\":[";
  const auto allow = ctx_.blocklist->rules(true);
  for (size_t i = 0; i < allow.size(); i++) j += (i ? "," : "") + q(allow[i]);
  j += "]},\"clients\":[";
  const auto clients = ctx_.clients->snapshot();
  for (size_t i = 0; i < clients.size(); i++) {
    const app::ClientInfo& c = clients[i];
    if (i) j += ",";
    j += "{\"ip\":" + q(IPAddress(c.ip).toString()) + ",\"mac\":" + q(macString(c.mac)) +
         ",\"blocked\":" + String(c.blocked) + ",\"allowed\":" + String(c.allowed) +
         ",\"banned\":" + b(c.banned) + "}";
  }
  j += "]}";
  ctx_.server->send(200, "application/json", j);
}

void Dashboard::handleGetConfig() {
  if (!guard(Access::kPublic)) return;
  const config::AppConfig& c = *ctx_.config;
  String j = "{\"up_pri\":" + q(config::providerName(c.primary)) +
             ",\"up_sec\":" + q(config::providerName(c.secondary));
  j += ",\"up_doh\":" + String(b(c.dohFallback)) + ",\"up_plain\":" + b(c.plainFallback);
  j += ",\"up_cip\":" + q(c.customIp) + ",\"up_cip2\":" + q(c.customIp2) +
       ",\"up_cname\":" + q(c.customName) + ",\"up_cdoh\":" + b(c.customDoh);
  j += ",\"pad\":" + String(b(c.padding)) + ",\"ad\":" + b(c.passAd) + ",\"blk_ttl\":" + String(c.blockedTtl);
  j += ",\"ff_canary\":" + String(b(c.firefoxCanary)) + ",\"icloud\":" + b(c.icloudRelay) +
       ",\"priv_rev\":" + b(c.privateReverse);
  j += ",\"tz\":" + q(c.timezone) + ",\"log\":" + String(c.logLevel) + "}";
  ctx_.server->send(200, "application/json", j);
}

void Dashboard::handleSetConfig() {
  if (!guard(Access::kAuth)) return;
  WebServer& s = *ctx_.server;
  config::AppConfig next = *ctx_.config;
  for (int i = 0; i < s.args(); i++) {
    const String k = s.argName(i);
    if (k == "plain") continue;  // WebServer exposes the raw body under "plain"
    const config::SetResult r = config::setField(next, k.c_str(), s.arg(i).c_str());
    if (r != config::SetResult::kOk) {
      sendText(400, "invalid value for " + k);
      return;
    }
  }
  const char* why = nullptr;
  if (!config::validate(next, &why)) {
    sendText(400, why);
    return;
  }
  if (!config::save(*ctx_.kv, next)) {
    sendText(500, "could not save settings");
    return;
  }
  const bool restart = config::requiresRestart(*ctx_.config, next);
  *ctx_.config = next;
  ctx_.log->log(LogLevel::kInfo, kTag, "settings saved%s", restart ? "; restarting" : "");
  if (restart) {
    sendText(200, "saved; restarting to apply DNS settings");
    delay(500);
    ESP.restart();
  }
  if (ctx_.applyLive) ctx_.applyLive(next);
  sendText(200, "saved");
}

void Dashboard::handlePassword() {
  if (!guard(Access::kAuthDuringSetup)) return;
  const char* why = nullptr;
  if (!ctx_.passwords->change(ctx_.server->arg("current").c_str(), ctx_.server->arg("next").c_str(), &why)) {
    sendText(400, why ? why : "rejected");
    return;
  }
  ctx_.log->log(LogLevel::kInfo, kTag, "dashboard password changed");
  sendText(200, "password changed; log in again with the new one");
}

void Dashboard::handleRule(bool add) {
  if (!guard(Access::kAuth)) return;
  const bool allow = ctx_.server->arg("list") == "allow";
  const String d = ctx_.server->arg("d");
  const bool ok = add ? ctx_.blocklist->addRule(allow, d) : ctx_.blocklist->removeRule(allow, d);
  sendText(ok ? 200 : 400, ok ? "ok" : (add ? "invalid domain or list full" : "not found"));
}

void Dashboard::handleBan() {
  if (!guard(Access::kAuth)) return;
  IPAddress ip;
  if (!ip.fromString(ctx_.server->arg("ip"))) {
    sendText(400, "invalid IP");
    return;
  }
  const bool banned = ctx_.clients->toggleBan(static_cast<uint32_t>(ip));
  sendText(200, banned ? "banned" : "unbanned");
}

void Dashboard::handlePause() {
  if (!guard(Access::kAuth)) return;
  const long secs = ctx_.server->arg("s").toInt();
  if (secs < 0 || secs > 86400) {
    sendText(400, "pause must be 0..86400 s");
    return;
  }
  ctx_.clients->pause(static_cast<uint32_t>(secs));
  sendText(200, secs ? "blocking paused" : "blocking paused until resumed");
}

void Dashboard::handleBlocklistSettings() {
  if (!guard(Access::kAuth)) return;
  WebServer& s = *ctx_.server;
  if (s.hasArg("u") && !ctx_.blocklist->setUrl(s.arg("u"))) {
    sendText(400, "URL must start with https://");
    return;
  }
  if (s.hasArg("t")) {
    const String t = s.arg("t");
    const int c = t.indexOf(':');
    const long h = c > 0 ? t.substring(0, c).toInt() : -1, m = c > 0 ? t.substring(c + 1).toInt() : -1;
    if (h < 0 || h > 23 || m < 0 || m > 59) {
      sendText(400, "time must be HH:MM");
      return;
    }
    ctx_.blocklist->setTime(static_cast<uint8_t>(h), static_cast<uint8_t>(m));
  }
  sendText(200, "saved");
}

// Uploads: the auth check runs once at UPLOAD_FILE_START (before any data is written).
void Dashboard::handleListUpload() {
  HTTPUpload& u = ctx_.server->upload();
  static File file;
  switch (u.status) {
    case UPLOAD_FILE_START: {
      const Check c = check(Access::kAuth);
      uploadAuthorized_ = c.ok;
      uploadResult_ = c.ok ? "upload incomplete" : c.message;
      if (c.ok) file = LittleFS.open(kUploadTmp, "w");
      break;
    }
    case UPLOAD_FILE_WRITE:
      if (uploadAuthorized_ && file && file.write(u.buf, u.currentSize) != u.currentSize) {
        file.close();
        uploadResult_ = "not enough flash";
      }
      break;
    case UPLOAD_FILE_END:
      if (!uploadAuthorized_) break;
      if (file) {
        file.close();
        const update::UpdateReport r = ctx_.blocklist->installUpload(kUploadTmp);
        uploadResult_ = String(update::updateStatusName(r.status)) + ": " + r.detail;
      }
      LittleFS.remove(kUploadTmp);
      break;
    case UPLOAD_FILE_ABORTED:
      if (file) file.close();
      LittleFS.remove(kUploadTmp);
      uploadResult_ = "upload aborted";
      break;
  }
}

void Dashboard::handleListUploadDone() {
  if (!uploadAuthorized_) {
    guard(Access::kAuth);  // sends the proper 401/403/429
    return;
  }
  sendText(uploadResult_.startsWith("updated") ? 200 : 400, uploadResult_);
}

void Dashboard::handleFirmwareUpload() {
  HTTPUpload& u = ctx_.server->upload();
  if (u.status == UPLOAD_FILE_START) {
    uploadAuthorized_ = check(Access::kAuth).ok;
    if (!uploadAuthorized_) return;
    ctx_.log->log(LogLevel::kInfo, "ota", "firmware upload: %s", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (!uploadAuthorized_) {
    return;
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (Update.end(true))
      ctx_.log->log(LogLevel::kInfo, "ota", "firmware %u bytes OK", u.totalSize);
    else
      Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    Update.abort();
  }
}

void Dashboard::handleFirmwareUploadDone() {
  if (!uploadAuthorized_) {
    guard(Access::kAuth);
    return;
  }
  const bool ok = !Update.hasError() && Update.isFinished();
  sendText(ok ? 200 : 500,
           ok ? "firmware accepted; rebooting (rolls back if unhealthy)" : "firmware update failed");
  if (ok) {
    delay(500);
    ESP.restart();
  }
}

}  // namespace web
