#include "web/dashboard.h"

#include <LittleFS.h>
#include <Update.h>
#include <WiFi.h>
#include <mbedtls/base64.h>

#include <ctime>

#include "platform/restart_info.h"
#include "platform/watchdog.h"
#include "util/civil_time.h"
#include "util/send_deadline.h"
#include "web/page.h"
#include "web/portal.h"

namespace web {

using hal::LogLevel;

namespace {

constexpr const char* kTag = "web";
constexpr const char* kCsrfHeader = "X-Requested-With";
constexpr const char* kCsrfValue = "adblock";
constexpr const char* kUploadTmp = "/upload.tmp";
constexpr const char* kSessionCookie = "ab_session";
constexpr size_t kPageSendPiece = 1436;  // one TCP segment
constexpr uint32_t kPageSendBudgetMs = 20000;

// Where the dashboard's "Check for updates" looks for update.json and the firmware
// (published to GitHub Pages by release.yml: Pages sends CORS headers, release
// downloads don't). Forks: point this at their own Pages site.
#ifndef UPDATE_BASE_URL
#define UPDATE_BASE_URL "https://denzilrdz.github.io/esp32-s3-adblock/"
#endif

// The dashboard page may only fetch from the device itself and the update site.
String pageCsp() {
  String csp =
      "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'";
  char origin[96];
  if (auth::urlOrigin(UPDATE_BASE_URL, origin, sizeof(origin))) {
    csp += ' ';
    csp += origin;
  }
  csp += "; frame-ancestors 'none'";
  return csp;
}

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

String formatTime(int64_t unixSeconds) {
  if (unixSeconds <= 0) return "never";
  const time_t t = static_cast<time_t>(unixSeconds);
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

// The page (46 KB, several TCP send buffers) and settings exports go out in pieces under
// one deadline: a client reading a trickle at a time would otherwise hold the single web
// task for hours (each byte sent resets NetworkClient's retry count). Normal clients
// take well under a second; a cut-off page just reloads.
void Dashboard::sendBody(const char* data, size_t len, const char* type, bool progmem) {
  WebServer& s = *ctx_.server;
  s.setContentLength(len);
  s.send(200, type, "");
  const util::SendResult r =
      util::sendWithDeadline(len, kPageSendPiece, kPageSendBudgetMs, *ctx_.clock, [&](size_t off, size_t n) {
        if (progmem)
          s.sendContent_P(data + off, n);
        else
          s.sendContent(data + off, n);
        if (ctx_.alive) ctx_.alive();
        return s.client().connected();
      });
  if (!r.complete) {
    ctx_.log->log(LogLevel::kWarn, kTag, "send to %s cut off after %u of %u bytes (slow client)",
                  s.client().remoteIP().toString().c_str(), static_cast<unsigned>(r.sent),
                  static_cast<unsigned>(len));
    s.client().stop();
  }
}

void Dashboard::uploadProgress() {
  platform::feedWatchdog();  // skipped while the web task is off the hardware watchdog
  if (ctx_.alive) ctx_.alive();
}

void Dashboard::sendText(int code, const String& text) {
  ctx_.server->send(code, "text/plain", text);
}

Dashboard::Check Dashboard::postChecks() {
  WebServer& s = *ctx_.server;
  if (s.method() != HTTP_POST) return {false, 405, "use POST"};
  if (s.header(kCsrfHeader) != kCsrfValue) return {false, 403, "missing X-Requested-With header"};
  if (!auth::originAllowed(s.header("Origin").c_str(), s.header("Referer").c_str(),
                           WiFi.localIP().toString().c_str(), ctx_.hostname))
    return {false, 403, "cross-site request refused"};
  return {true, 200, ""};
}

Dashboard::Check Dashboard::verifyPassword(const String& user, const String& pass) {
  WebServer& s = *ctx_.server;
  const uint32_t client = static_cast<uint32_t>(s.client().remoteIP());
  if (!ctx_.logins->allowed(client)) return {false, 429, "too many failed logins; try again later"};
  if (!ctx_.passwords->verify(user.c_str(), pass.c_str())) {
    ctx_.logins->onFailure(client);
    ctx_.log->log(LogLevel::kWarn, kTag, "failed login from %s", s.client().remoteIP().toString().c_str());
    // Global brute-force brake without a lockout anyone could trigger: the single
    // web task spends a fixed second per failure (on top of PBKDF2), capping
    // guesses at ~1/s in total however many addresses an attacker uses.
    delay(1000);
    return {false, 401, "wrong user name or password"};
  }
  ctx_.logins->onSuccess(client);
  return {true, 200, ""};
}

bool Dashboard::hasSession() {
  char token[auth::SessionStore::kTokenLength + 1];
  return auth::cookieValue(ctx_.server->header("Cookie").c_str(), kSessionCookie, token, sizeof(token)) &&
         ctx_.sessions->valid(token);
}

Dashboard::Check Dashboard::check(Access access) {
  WebServer& s = *ctx_.server;
  if (!auth::hostAllowed(s.header("Host").c_str(), WiFi.localIP().toString().c_str(), ctx_.hostname))
    return {false, 403, "unknown Host header (use the device IP or its .local name)"};
  if (access == Access::kPublic) return {true, 200, ""};
  if (access != Access::kRead) {
    const Check c = postChecks();
    if (!c.ok) return c;
  }
  if (!hasSession()) {
    // Scripts may still send Basic Auth; browsers get a plain 401 and the page's own
    // login form (no WWW-Authenticate, so no browser pop-up).
    String user, pass;
    if (!parseBasicAuth(s.header("Authorization"), user, pass)) return {false, 401, "login required"};
    const Check c = verifyPassword(user, pass);
    if (!c.ok) return c;
  }
  if (ctx_.passwords->mustChange() && access == Access::kAuth)
    return {false, 403, "set a dashboard password first"};
  return {true, 200, ""};
}

bool Dashboard::guard(Access access) {
  const Check c = check(access);
  if (c.ok) return true;
  if (c.code == 429) {
    const uint32_t client = static_cast<uint32_t>(ctx_.server->client().remoteIP());
    ctx_.server->sendHeader("Retry-After", String(ctx_.logins->retryAfterSeconds(client)));
  }
  sendText(c.code, c.message);
  return false;
}

void Dashboard::begin() {
  WebServer& s = *ctx_.server;
  const char* headers[] = {"Host", "Origin", "Referer", "Cookie", kCsrfHeader};
  s.collectHeaders(headers, sizeof(headers) / sizeof(headers[0]));  // Authorization is always kept

  s.on("/", HTTP_GET, [this]() {
    if (!guard(Access::kPublic)) return;
    static const String csp = pageCsp();
    ctx_.server->sendHeader("Content-Security-Policy", csp);
    ctx_.server->sendHeader("X-Frame-Options", "DENY");
    sendBody(kPage, sizeof(kPage) - 1, "text/html", true);
  });
  s.on("/api/stats", HTTP_GET, [this]() { handleStats(); });
  s.on("/api/config", HTTP_GET, [this]() { handleGetConfig(); });
  s.on("/api/config", HTTP_POST, [this]() { handleSetConfig(); });
  s.on("/api/login", HTTP_POST, [this]() { handleLogin(); });
  s.on("/api/logout", HTTP_POST, [this]() { handleLogout(); });
  s.on("/api/password", HTTP_POST, [this]() { handlePassword(); });
  s.on("/api/rules/add", HTTP_POST, [this]() { handleRule(true); });
  s.on("/api/rules/remove", HTTP_POST, [this]() { handleRule(false); });
  s.on("/api/rewrites/add", HTTP_POST, [this]() { handleRewrite(true); });
  s.on("/api/rewrites/remove", HTTP_POST, [this]() { handleRewrite(false); });
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
  s.on("/api/upstreams/test", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    if (ctx_.dns->startUpstreamTest())
      sendText(200, "testing every upstream; results appear under Upstream DNS");
    else
      sendText(409, "an upstream test is already running");
  });
  s.on("/api/wifi/forget", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    sendText(200, "Wi-Fi forgotten; rebooting into the setup portal");
    forgetWifi();
    delay(500);
    platform::restart("Wi-Fi forgotten (dashboard)");
  });
#ifdef ADBLOCK_SELFTEST
  s.on("/api/selftest", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    const String what = ctx_.server->arg("hang");
    sendText(200, "self-test: hanging " + what);
    ctx_.server->client().stop();  // the answer must leave before a web-task hang
    if (ctx_.selftest) ctx_.selftest(what);
  });
#endif
  s.on("/api/reboot", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    sendText(200, "rebooting");
    delay(500);
    platform::restart("Reboot button (dashboard)");
  });
  s.on("/api/settings/export", HTTP_GET, [this]() { handleExport(); });
  s.on(
      "/api/settings/import", HTTP_POST, [this]() { handleImportDone(); },
      [this]() { handleImportUpload(); });
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
  if (!guard(Access::kRead)) return;
  const uint32_t up = millis() / 1000;
  char uptime[24];
  snprintf(uptime, sizeof(uptime), "%lud %luh %lum", static_cast<unsigned long>(up / 86400),
           static_cast<unsigned long>((up % 86400) / 3600), static_cast<unsigned long>((up % 3600) / 60));
  const app::BlocklistStatus bl = ctx_.blocklist->status();
  const app::DnsStats d = ctx_.dns->stats();
  const cache::CacheStats cs = ctx_.dns->cacheStats();
  const app::UpstreamSnapshot us = ctx_.dns->upstreams();
  char hhmm[8];
  snprintf(hhmm, sizeof(hhmm), "%02u:%02u", bl.hour, bl.minute);

  String j;
  j.reserve(4096);
  j += "{\"version\":" + q(ctx_.version) + ",\"hostname\":" + q(ctx_.hostname) +
       ",\"updateUrl\":" + q(UPDATE_BASE_URL);
  j += ",\"ip\":" + q(WiFi.localIP().toString()) + ",\"rssi\":" + String(WiFi.RSSI());
  j += ",\"uptime\":" + q(uptime) + ",\"heap\":" + String(ESP.getFreeHeap()) +
       ",\"heapMin\":" + String(ESP.getMinFreeHeap()) + ",\"heapBlock\":" + String(ESP.getMaxAllocHeap()) +
       ",\"psram\":" + String(ESP.getFreePsram()) + ",\"temp\":" + String(temperatureRead(), 1);
  j += ",\"setupRequired\":" + String(b(ctx_.passwords->mustChange()));
  if (ctx_.restart) {
    const diag::RestartInfo& r = *ctx_.restart;
    char why[160];
    diag::describe(r, why, sizeof(why));
    j += ",\"restart\":{\"cause\":" + q(diag::resetCauseName(r.cause)) + ",\"summary\":" + q(why) +
         ",\"crash\":";
    if (r.crash.present) {
      char bt[200];
      diag::formatBacktrace(r.crash, bt, sizeof(bt));
      j += "{\"thisBoot\":" + String(b(r.crashThisBoot())) + ",\"task\":" + q(r.crash.task) +
           ",\"reason\":" + q(r.crash.reason) + ",\"backtrace\":" + q(bt) +
           ",\"corrupted\":" + b(r.crash.corrupted) + ",\"elf\":" + q(r.crash.elfSha) + "}";
    } else {
      j += "null";
    }
    j += "}";
  }
  j += ",\"timeSynced\":" + String(b(bl.timeSynced)) + ",\"now\":" + q(formatTime(time(nullptr)));
  {
    const sched::RebootPlan& rp = ctx_.config->reboot;
    util::CivilTime next;
    char when[20] = "";
    if (ctx_.nextReboot && ctx_.nextReboot(next))
      snprintf(when, sizeof(when), "%04d-%02d-%02d %02d:%02d", next.year, next.month, next.day, next.hour,
               next.minute);
    j += ",\"reboot\":{\"mode\":" + q(sched::rebootModeName(rp.mode)) + ",\"next\":" + q(when) +
         ",\"nextDay\":" + String(when[0] ? util::weekday(next) : -1) + "}";
  }
  j += ",\"blocking\":" + String(b(ctx_.clients->blockingOn())) +
       ",\"resumeIn\":" + String(ctx_.clients->resumeInSeconds());
  j += ",\"dns\":{\"queries\":" + String(d.queries) + ",\"tcp\":" + String(d.tcpQueries) +
       ",\"blocked\":" + String(d.blocked) + ",\"local\":" + String(d.local) +
       ",\"cacheHits\":" + String(d.cacheHits) + ",\"forwarded\":" + String(d.forwarded) +
       ",\"servfail\":" + String(d.servfail) + ",\"rewritten\":" + String(d.rewritten) +
       ",\"cacheEntries\":" + String(cs.entries) + "}";
  j += ",\"plainFallback\":" + String(b(us.plainFallback)) + ",\"upstreamTest\":" + b(us.testing) +
       ",\"upstreams\":[";
  for (size_t i = 0; i < us.count; i++) {
    const upstream::UpstreamStatus& u = us.status[i];
    if (i) j += ",";
    j += "{\"name\":" + q(u.name) + ",\"encrypted\":" + b(u.authenticated) +
         ",\"state\":" + q(upstream::healthStateName(u.state)) + ",\"ok\":" + String(u.stats.ok) +
         ",\"failed\":" + String(u.stats.failed) + ",\"latencyMs\":" + String(u.stats.lastLatencyMs);
    if (u.probe.result != upstream::ProbeResult::kNone) {
      j += ",\"test\":{\"result\":" + q(upstream::probeResultName(u.probe.result)) +
           ",\"ms\":" + String(u.probe.latencyMs) + ",\"rcode\":" + String(u.probe.rcode) +
           ",\"tlsError\":" + String(u.probe.tlsError) + "}";
    }
    j += "}";
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
  j += "]},\"rewrites\":{\"max\":" + String(rules::RewriteTable::kMax) + ",\"items\":[";
  if (ctx_.rewrites) {
    const auto rw = ctx_.rewrites->list();
    for (size_t i = 0; i < rw.size(); i++) {
      const rules::RewriteView& r = rw[i];
      const char* kind = r.kind == rules::TargetKind::kIpv4   ? "ipv4"
                         : r.kind == rules::TargetKind::kIpv6 ? "ipv6"
                                                              : "alias";
      j += String(i ? "," : "") + "{\"d\":" + q(r.domain) + ",\"t\":" + q(r.target) + ",\"k\":\"" + kind +
           "\",\"s\":" + String(r.secondsLeft) + ",\"wait\":" + b(r.pending) + "}";
    }
  }
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
  if (!guard(Access::kRead)) return;
  const config::AppConfig& c = *ctx_.config;
  String j = "{\"up_pri\":" + q(config::providerName(c.primary)) +
             ",\"up_sec\":" + q(config::providerName(c.secondary));
  j += ",\"up_doh\":" + String(b(c.dohFallback)) + ",\"up_plain\":" + b(c.plainFallback);
  j += ",\"up_cip\":" + q(c.customIp) + ",\"up_cip2\":" + q(c.customIp2) +
       ",\"up_cname\":" + q(c.customName) + ",\"up_cdoh\":" + b(c.customDoh);
  j += ",\"pad\":" + String(b(c.padding)) + ",\"ad\":" + b(c.passAd) + ",\"blk_ttl\":" + String(c.blockedTtl);
  j += ",\"ff_canary\":" + String(b(c.firefoxCanary)) + ",\"icloud\":" + b(c.icloudRelay) +
       ",\"priv_rev\":" + b(c.privateReverse);
  char rbTime[8];
  snprintf(rbTime, sizeof(rbTime), "%02u:%02u", c.reboot.hour % 24u, c.reboot.minute % 60u);
  j += ",\"tz\":" + q(c.timezone) + ",\"log\":" + String(c.logLevel);
  j += ",\"rb_mode\":" + q(sched::rebootModeName(c.reboot.mode)) + ",\"rb_day\":" + String(c.reboot.weekday) +
       ",\"rb_time\":" + q(rbTime) + "}";
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
    platform::restart("DNS settings changed");
  }
  if (ctx_.applyLive) ctx_.applyLive(next);
  sendText(200, "saved");
}

void Dashboard::handleLogin() {
  Check c = check(Access::kPublic);
  if (c.ok) c = postChecks();
  if (c.ok) c = verifyPassword(ctx_.server->arg("user"), ctx_.server->arg("pass"));
  if (!c.ok) {
    if (c.code == 429) {
      const uint32_t client = static_cast<uint32_t>(ctx_.server->client().remoteIP());
      ctx_.server->sendHeader("Retry-After", String(ctx_.logins->retryAfterSeconds(client)));
    }
    sendText(c.code, c.message);
    return;
  }
  char token[auth::SessionStore::kTokenLength + 1];
  ctx_.sessions->create(token);
  // No Max-Age: a browser-session cookie; the board ends it after 30 min idle or 24 h.
  ctx_.server->sendHeader("Set-Cookie",
                          String(kSessionCookie) + "=" + token + "; Path=/; HttpOnly; SameSite=Strict");
  ctx_.server->sendHeader("Cache-Control", "no-store");
  sendText(200, ctx_.passwords->mustChange() ? "setup" : "ok");
}

void Dashboard::handleLogout() {
  Check c = check(Access::kPublic);
  if (c.ok) c = postChecks();
  if (!c.ok) {
    sendText(c.code, c.message);
    return;
  }
  char token[auth::SessionStore::kTokenLength + 1];
  if (auth::cookieValue(ctx_.server->header("Cookie").c_str(), kSessionCookie, token, sizeof(token)))
    ctx_.sessions->revoke(token);
  ctx_.server->sendHeader("Set-Cookie",
                          String(kSessionCookie) + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
  sendText(200, "logged out");
}

void Dashboard::handlePassword() {
  if (!guard(Access::kAuthDuringSetup)) return;
  const char* why = nullptr;
  if (!ctx_.passwords->change(ctx_.server->arg("current").c_str(), ctx_.server->arg("next").c_str(), &why)) {
    sendText(400, why ? why : "rejected");
    return;
  }
  ctx_.log->log(LogLevel::kInfo, kTag, "dashboard password changed");
  ctx_.sessions->revokeAll();  // every browser, this one included, logs in again
  ctx_.server->sendHeader("Set-Cookie",
                          String(kSessionCookie) + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
  sendText(200, "password changed; log in with the new one");
}

void Dashboard::handleRule(bool add) {
  if (!guard(Access::kAuth)) return;
  const bool allow = ctx_.server->arg("list") == "allow";
  const String d = ctx_.server->arg("d");
  const bool ok = add ? ctx_.blocklist->addRule(allow, d) : ctx_.blocklist->removeRule(allow, d);
  sendText(ok ? 200 : 400, ok ? "ok" : (add ? "invalid domain or list full" : "not found"));
}

void Dashboard::handleRewrite(bool add) {
  if (!guard(Access::kAuth)) return;
  if (!ctx_.rewrites) {
    sendText(503, "rewrites unavailable");
    return;
  }
  WebServer& s = *ctx_.server;
  const String d = s.arg("d"), t = s.arg("t");
  if (d.length() > 300 || t.length() > 300) {
    sendText(400, "too long");
    return;
  }
  rules::RewriteStatus st;
  if (add) {
    // Whole minutes, 1..1440. toInt() reads "15abc" as 15: insist on digits only.
    const String m = s.arg("m");
    bool digits = m.length() > 0 && m.length() <= 5;
    for (size_t i = 0; digits && i < m.length(); i++) digits = m[i] >= '0' && m[i] <= '9';
    st = digits ? ctx_.rewrites->add(d, t, static_cast<uint32_t>(m.toInt()))
                : rules::RewriteStatus::kBadDuration;
  } else {
    st = ctx_.rewrites->remove(d, t);
  }
  const int code = rules::rewriteOk(st)                                                         ? 200
                   : st == rules::RewriteStatus::kNotFound                                      ? 404
                   : st == rules::RewriteStatus::kConflict || st == rules::RewriteStatus::kFull ? 409
                                                                                                : 400;
  sendText(code, rules::rewriteStatusMessage(st));
}

void Dashboard::handleBan() {
  if (!guard(Access::kAuth)) return;
  IPAddress ip;
  if (!ip.fromString(ctx_.server->arg("ip"))) {
    sendText(400, "invalid IP");
    return;
  }
  switch (ctx_.clients->toggleBan(static_cast<uint32_t>(ip))) {
    case app::ClientTable::BanResult::kBanned: sendText(200, "banned"); break;
    case app::ClientTable::BanResult::kUnbanned: sendText(200, "unbanned"); break;
    case app::ClientTable::BanResult::kListFull:
      sendText(409, "ban list full (" + String(app::ClientTable::kMaxBans) + "): unban a client first");
      break;
  }
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
    String t = s.arg("t");
    t.trim();
    uint8_t h = 0, m = 0;
    if (!util::parseHhMm(t.c_str(), h, m)) {
      sendText(400, "time must be HH:MM");
      return;
    }
    ctx_.blocklist->setTime(h, m);
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
      uploadProgress();  // the whole upload runs inside one handleClient() call
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
    // The whole upload (and each sector erase) runs inside one handleClient() call: a
    // 1.3 MB image over a weak link took longer than the 5 s task watchdog and panicked
    // the web task mid-upload (found on hardware, 2026-10-15).
    uploadProgress();
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    uploadProgress();  // end() hashes and verifies the image before activating it
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
    platform::restart("firmware update (dashboard)");
  }
}

// ---- settings file (config/backup.h) ----------------------------------------------

void Dashboard::handleExport() {
  if (!guard(Access::kRead)) return;
  config::Backup b;
  b.settings = *ctx_.config;
  const app::BlocklistStatus bl = ctx_.blocklist->status();
  if (bl.url != app::BlocklistManager::defaultUrl()) b.blocklistUrl = bl.url.c_str();  // "" = default
  b.blocklistHour = bl.hour;
  b.blocklistMinute = bl.minute;
  for (const String& d : ctx_.blocklist->rules(false)) config::addRule(b.blockRules, b.blockCount, d.c_str());
  for (const String& d : ctx_.blocklist->rules(true)) config::addRule(b.allowRules, b.allowCount, d.c_str());
  b.bans = ctx_.clients->bans();

  const time_t now = time(nullptr);
  struct tm tmv;
  localtime_r(&now, &tmv);
  char exported[24] = "", file[64];
  if (ctx_.clock->wallClockSynced()) {
    strftime(exported, sizeof(exported), "%Y-%m-%d %H:%M", &tmv);
    char stamp[16];
    strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M", &tmv);
    snprintf(file, sizeof(file), "%s-settings-%s.json", ctx_.hostname, stamp);
  } else {
    snprintf(file, sizeof(file), "%s-settings.json", ctx_.hostname);
  }
  config::BackupMeta meta;
  meta.firmware = ctx_.version;
  meta.hostname = ctx_.hostname;
  meta.exported = exported;
  std::string text;
  text.reserve(2048 + b.blockRules.size() + b.allowRules.size() + b.blockCount * 8 + b.allowCount * 8);
  config::writeBackup(b, meta, text);
  ctx_.server->sendHeader("Content-Disposition", String("attachment; filename=\"") + file + "\"");
  ctx_.server->sendHeader("Cache-Control", "no-store");
  sendBody(text.data(), text.size(), "application/json", false);
  ctx_.log->log(LogLevel::kInfo, kTag, "settings exported (%u bytes)", static_cast<unsigned>(text.size()));
}

// The file is collected in one PSRAM buffer (kMaxBackupBytes at most, sized from the
// request), then validated as a whole before anything changes.
void Dashboard::handleImportUpload() {
  HTTPUpload& u = ctx_.server->upload();
  switch (u.status) {
    case UPLOAD_FILE_START: {
      const Check c = check(Access::kAuth);
      uploadAuthorized_ = c.ok;
      importBuf_.reset();
      importCap_ = importLen_ = 0;
      importError_ = nullptr;
      importErrorCode_ = 400;
      if (!c.ok) break;
      // The request size bounds the file (multipart adds a few hundred bytes).
      const int body = ctx_.server->clientContentLength();
      importCap_ = body > 0 && static_cast<size_t>(body) < config::kMaxBackupBytes ? static_cast<size_t>(body)
                                                                                   : config::kMaxBackupBytes;
      importBuf_ = platform::makeLargeBuffer(importCap_);
      if (!importBuf_) {
        importError_ = "not enough free memory for the file";
        importErrorCode_ = 507;
      }
      break;
    }
    case UPLOAD_FILE_WRITE:
      uploadProgress();
      if (!uploadAuthorized_ || importError_) break;
      if (u.currentSize > importCap_ - importLen_) {
        importError_ = "file too large for a settings file";
        importErrorCode_ = 413;
        importBuf_.reset();
        break;
      }
      memcpy(importBuf_.get() + importLen_, u.buf, u.currentSize);
      importLen_ += u.currentSize;
      break;
    case UPLOAD_FILE_END: break;
    case UPLOAD_FILE_ABORTED:
      importError_ = "upload aborted";
      importBuf_.reset();
      break;
  }
}

void Dashboard::handleImportDone() {
  if (!uploadAuthorized_) {
    guard(Access::kAuth);  // sends the proper 401/403/429
    return;
  }
  uploadAuthorized_ = false;
  platform::LargeBuffer buf = std::move(importBuf_);
  const size_t len = importLen_;
  importLen_ = importCap_ = 0;
  if (importError_) {
    sendText(importErrorCode_, String("nothing changed: ") + importError_);
    return;
  }
  if (!buf || len == 0) {
    sendText(400, "no settings file received (or it is empty)");
    return;
  }
  config::Backup b;
  char why[160];
  if (!config::parseBackup(reinterpret_cast<const char*>(buf.get()), len, *ctx_.config, b, why,
                           sizeof(why))) {
    ctx_.log->log(LogLevel::kWarn, kTag, "settings import refused: %s", why);
    sendText(400, String("nothing changed: ") + why);
    return;
  }
  buf.reset();

  // Apply. Settings first: if they can't be saved, nothing else changes either.
  const config::AppConfig before = *ctx_.config;
  if (b.hasSettings && !config::save(*ctx_.kv, b.settings)) {
    sendText(500, "could not save settings; nothing changed");
    return;
  }
  String done;
  auto part = [&](const String& what) { done += (done.length() ? ", " : "") + what; };
  bool writeFailed = false;
  if (b.hasSettings) part("settings");
  if (b.hasBlocklist) {
    ctx_.blocklist->setUrl(String(b.blocklistUrl.c_str()));  // validated: "" or https://
    ctx_.blocklist->setTime(b.blocklistHour, b.blocklistMinute);
    part("blocklist URL and time");
  }
  if (b.hasBlockRules) {
    writeFailed |= !ctx_.blocklist->replaceRules(false, b.blockRules);
    part(String(b.blockCount) + " block rule" + (b.blockCount == 1 ? "" : "s"));
  }
  if (b.hasAllowRules) {
    writeFailed |= !ctx_.blocklist->replaceRules(true, b.allowRules);
    part(String(b.allowCount) + " allow rule" + (b.allowCount == 1 ? "" : "s"));
  }
  if (b.hasBans) {
    ctx_.clients->replaceBans(b.bans);
    part(String(b.bans.size()) + " banned client" + (b.bans.size() == 1 ? "" : "s"));
  }
  String msg = done.length() ? "imported " + done : String("the file has nothing to import");
  if (b.ignoredKeys) msg += " (" + String(b.ignoredKeys) + " unknown entries skipped)";
  if (writeFailed) msg += "; warning: a rule file could not be saved to flash";
  ctx_.log->log(LogLevel::kInfo, kTag, "settings import: %s", msg.c_str());
  if (!b.hasSettings) {
    sendText(200, msg);
    return;
  }
  *ctx_.config = b.settings;
  if (config::requiresRestart(before, b.settings)) {
    sendText(200, msg + "; restarting to apply DNS settings");
    delay(500);
    platform::restart("settings imported (dashboard)");
  }
  if (ctx_.applyLive) ctx_.applyLive(b.settings);
  sendText(200, msg);
}

}  // namespace web
