// ESP32-S3 AdBlock — DNS sinkhole + web dashboard (fork of esp32-c3-adblock).
// DNS runs in its own FreeRTOS tasks (src/tasks/dns_service.*) and forwards over
// DNS-over-TLS/DoH (src/platform/transports.*). The blocklist (48-bit hashes, format
// v2) lives in PSRAM and refreshes daily at 02:00 IST (src/app/blocklist_manager.*).
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include <esp_netif.h>
#include <esp_ota_ops.h>
#include <esp_sntp.h>
#include <esp_task_wdt.h>
#include "lwip/tcpip.h"
#include "app/blocklist_manager.h"
#include "platform/esp_http.h"
#include "platform/littlefs_fs.h"
#include "platform/nvs_kv_store.h"
#include "platform/esp_clock.h"
#include "platform/esp_random.h"
#include "platform/psram.h"
#include "platform/rtos.h"
#include "platform/serial_logger.h"
#include "platform/transports.h"
#include "tasks/dns_service.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- globals ----
#if CONFIG_IDF_TARGET_ESP32S3
static const char* HOSTNAME = "s3adblock";
#else
static const char* HOSTNAME = "c3adblock";
#endif
WebServer web(80);
uint32_t totalBlocked = 0, totalAllowed = 0;

// Guards the client table, bans and pause state: the DNS task reads them through
// AppPolicy while web handlers in loop() modify them.
static platform::RecursiveMutex gState;
using StateLock = platform::RecursiveLockGuard;

static platform::EspClock gClock;
static platform::EspRandom gRandom;
static platform::SerialLogger gLog;
static app::DnsService* gDns = nullptr;
static platform::LittleFsFileSystem gFs;
static platform::NvsKvStore gKv("adblock");
static platform::EspHttpClient gHttp;
static app::BlocklistManager* gBlocklist = nullptr;

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; bool macPending; uint8_t macTries; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- persistence ----------
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
// Caller holds gState. MAC addresses are filled in later by resolvePendingMacs():
// the ARP table may only be read from lwIP's own thread.
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    memset(c->mac, 0, 6); c->macPending = true; c->macTries = 0;
    return c;
  }
  return nullptr;
}

// ARP lookups run inside the lwIP thread via tcpip_callback(); results are copied
// back under gState by the maintenance task. No lock is taken in the lwIP thread.
struct MacJob { int n; uint32_t ip[8]; uint8_t mac[8][6]; bool found[8]; SemaphoreHandle_t done; };
static void macJobInLwip(void* ctx) {
  MacJob* job = static_cast<MacJob*>(ctx);
  for (int k = 0; k < job->n; k++) {
    ip4_addr_t ipa; ipa.addr = job->ip[k];
    struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
    job->found[k] = false;
    for (struct netif* nif = netif_list; nif && !job->found[k]; nif = nif->next)
      if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(job->mac[k], eth->addr, 6); job->found[k] = true; }
  }
  xSemaphoreGive(job->done);
}
static void resolvePendingMacs() {
  static MacJob job = {0, {}, {}, {}, xSemaphoreCreateBinary()};
  static bool inFlight = false;
  if (inFlight && xSemaphoreTake(job.done, 0) != pdTRUE) return;  // previous job still queued
  inFlight = false;
  job.n = 0;
  {
    StateLock g(gState);
    for (int i = 0; i < numClients && job.n < 8; i++)
      if (clients[i].macPending && (clients[i].ip >> 24) != 127) job.ip[job.n++] = clients[i].ip;
  }
  if (!job.n || tcpip_callback(macJobInLwip, &job) != ERR_OK) return;
  inFlight = true;
  if (xSemaphoreTake(job.done, pdMS_TO_TICKS(500)) != pdTRUE) return;  // collect next time
  inFlight = false;
  StateLock g(gState);
  for (int k = 0; k < job.n; k++)
    for (int i = 0; i < numClients; i++)
      if (clients[i].ip == job.ip[k] && clients[i].macPending) {
        if (job.found[k]) { memcpy(clients[i].mac, job.mac[k], 6); clients[i].macPending = false; }
        else if (++clients[i].macTries >= 10) clients[i].macPending = false;  // give up quietly
      }
}

// ---------- DNS policy ----------
// Called from the DNS task for every valid query: banned clients, pause, then the
// blocklist matcher (custom allow > custom block > main list, parent domains).
class AppPolicy final : public dns::IQueryPolicy {
 public:
  dns::PolicyAction decide(const dns::Query& q, uint32_t clientIpv4) override {
    if ((ntohl(clientIpv4) >> 24) == 127) return dns::PolicyAction::kForward;  // the device's own lookups
    Dev* c;
    bool on;
    {
      StateLock g(gState);
      c = getClient(clientIpv4);
      if (c && c->banned) { c->blocked++; totalBlocked++; return dns::PolicyAction::kBan; }
      on = blockingOn;
    }
    const bool blocked = on && gBlocklist &&
                         gBlocklist->matcher().match(q.qname, q.qnameLen) == blocklist::MatchResult::kBlocked;
    StateLock g(gState);
    if (blocked) { totalBlocked++; if (c) c->blocked++; return dns::PolicyAction::kBlock; }
    totalAllowed++; if (c) c->allowed++;
    return dns::PolicyAction::kForward;
  }
};
static AppPolicy gPolicy;

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  StateLock lock(gState);
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  const app::BlocklistStatus bl = gBlocklist->status();
  char when[40] = "never", hhmm[6];
  if (bl.lastAttempt > 0) { time_t t = (time_t)bl.lastAttempt; struct tm tmv; localtime_r(&t, &tmv); strftime(when, sizeof(when), "%Y-%m-%d %H:%M", &tmv); }
  snprintf(hhmm, sizeof(hhmm), "%02u:%02u", bl.hour, bl.minute);
  const String upstat = String(when) + " — " + bl.lastResult + (bl.timeSynced ? "" : " (clock not synced yet)");
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + bl.entries + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"psram\":" + ESP.getFreePsram() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(bl.url) + "\",\"uptime24\":\"" + hhmm + "\",\"upstat\":\"" + jesc(upstat) + "\"" +
             ",\"upok\":" + (bl.lastOk ? "true" : "false") + ",\"listBuilt\":" + String((long)bl.buildTime) +
             ",\"timeSynced\":" + (bl.timeSynced ? "true" : "false") +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  { const auto rules = gBlocklist->rules(false);
    for (size_t i = 0; i < rules.size(); i++) { j += (i ? "," : ""); j += "\"" + jesc(rules[i]) + "\""; } }
  j += "],\"allow\":[";
  { const auto rules = gBlocklist->rules(true);
    for (size_t i = 0; i < rules.size(); i++) { j += (i ? "," : ""); j += "\"" + jesc(rules[i]) + "\""; } }
  j += "]";
  if (gDns) {                                  // DNS service + encrypted upstream status
    const app::DnsStats d = gDns->stats();
    const cache::CacheStats cs = gDns->cacheStats();
    const app::UpstreamSnapshot us = gDns->upstreams();
    j += ",\"dns\":{\"queries\":" + String(d.queries) + ",\"blocked\":" + d.blocked +
         ",\"local\":" + d.local + ",\"cacheHits\":" + d.cacheHits + ",\"forwarded\":" + d.forwarded +
         ",\"servfail\":" + d.servfail + ",\"cacheEntries\":" + cs.entries + "}";
    j += ",\"plainFallback\":" + String(us.plainFallback ? "true" : "false") + ",\"upstreams\":[";
    for (size_t i = 0; i < us.count; i++) {
      const upstream::UpstreamStatus& u = us.status[i];
      j += (i ? "," : "");
      j += "{\"name\":\"" + jesc(u.name) + "\",\"encrypted\":" + (u.authenticated ? "true" : "false") +
           ",\"state\":\"" + upstream::healthStateName(u.state) + "\",\"ok\":" + u.stats.ok +
           ",\"failed\":" + u.stats.failed + ",\"latencyMs\":" + u.stats.lastLatencyMs + "}";
    }
    j += "]";
  }
  j += "}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  StateLock lock(gState);
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist upload (browser) ----------
// The file is written to /upload.tmp, then validated and installed by the manager;
// a bad upload never touches the live list.
static const char* UPLOAD_TMP = "/upload.tmp";
static bool upAuthOk = false;
static String upResult;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  const bool ok = upResult.startsWith("updated");
  web.send(ok ? 200 : 400, "text/plain", upResult);
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upResult = "upload incomplete";
      upFile = LittleFS.open(UPLOAD_TMP, "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile && upFile.write(u.buf, u.currentSize) != u.currentSize) { upFile.close(); upResult = "not enough flash"; }
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) {
        upFile.close();
        const update::UpdateReport r = gBlocklist->installUpload(UPLOAD_TMP);
        upResult = String(update::updateStatusName(r.status)) + ": " + r.detail;
      }
      LittleFS.remove(UPLOAD_TMP);
      Serial.printf("[ota] blocklist upload -> %s\n", upResult.c_str());
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove(UPLOAD_TMP);
      upResult = "upload aborted";
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

// Wall clock: SNTP via hard-coded Cloudflare time IPs (no DNS needed) plus the pool.
// Nothing time-of-day based (the 02:00 update) runs until the first sync.
static void startTimeSync() {
  sntp_set_time_sync_notification_cb([](struct timeval*) {
    if (!gClock.wallClockSynced()) gLog.log(hal::LogLevel::kInfo, "time", "clock synced (IST)");
    gClock.setSynced(true);
  });
  configTzTime("IST-5:30", "162.159.200.1", "162.159.200.123", "pool.ntp.org");
}

// The device's own lookups (blocklist host, NTP pool) go through our own DNS
// service on 127.0.0.1, so they are encrypted too. DHCP renewals overwrite the
// resolver, so this is re-applied periodically from loop().
static void pointResolverToSelf() {
  esp_netif_t* nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (!nif) return;
  esp_netif_dns_info_t dns = {};
  dns.ip.type = ESP_IPADDR_TYPE_V4;
  dns.ip.u_addr.ip4.addr = ESP_IP4TOADDR(127, 0, 0, 1);
  esp_netif_set_dns_info(nif, ESP_NETIF_DNS_MAIN, &dns);
}

// Encrypted upstream chain, in priority order (ARCHITECTURE.md §7.1). Hard-coded IPs:
// no plaintext bootstrap lookup. Plain UDP is only used if every encrypted one is Down.
static void startDnsService() {
  static upstream::ITransport* chain[] = {
      new platform::DotTransport("cloudflare-dot", "1.1.1.1", "cloudflare-dns.com"),
      new platform::DotTransport("cloudflare-dot-2", "1.0.0.1", "cloudflare-dns.com"),
      new platform::DotTransport("quad9-dot", "9.9.9.9", "dns.quad9.net"),
      new platform::DotTransport("quad9-dot-2", "149.112.112.112", "dns.quad9.net"),
      new platform::DohTransport("cloudflare-doh", "1.1.1.1", "cloudflare-dns.com"),
      new platform::DohTransport("cloudflare-doh-2", "1.0.0.1", "cloudflare-dns.com"),
      new platform::UdpTransport("quad9-udp", "9.9.9.9"),
      new platform::UdpTransport("cloudflare-udp", "1.1.1.1"),
  };
  app::DnsServiceConfig cfg;
  if (!platform::havePsram()) {        // lite profile (C3 / classic ESP32): small cache, UDP only
    cfg.cache.maxEntries = 512;
    cfg.cache.arenaBytes = 64 * 1024;
    cfg.pendingSlots = 16;
    cfg.tcpEnabled = false;
    cfg.replyCap = dns::kMaxUdpPayload;
  }
  gDns = new app::DnsService(cfg, gPolicy, gClock, gRandom, gLog, chain, sizeof(chain) / sizeof(chain[0]));
  if (!gDns->start()) Serial.println("[ERROR] DNS service failed to start");
}

// ---------- tasks ----------
// web (core 0, prio 3): dashboard + ArduinoOTA, so a slow HTTP client or a blocklist
// download in the maintenance task never stalls the other.
static void webTask(void*) {
  esp_task_wdt_add(nullptr);
  while (true) {
    web.handleClient();
    ArduinoOTA.handle();
    esp_task_wdt_reset();
    vTaskDelay(pdMS_TO_TICKS(2));
  }
}

static void feedWatchdog() { esp_task_wdt_reset(); }

// Firmware rollback: Arduino would mark a freshly OTA-flashed image valid at boot.
// We defer that until the new firmware has proved healthy (see maintainOtaHealth()).
extern "C" bool verifyRollbackLater() { return true; }  // overrides a weak C symbol

static void maintainOtaHealth() {
  static bool done = false;
  if (done) return;
  esp_ota_img_states_t state;
  if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &state) != ESP_OK ||
      state != ESP_OTA_IMG_PENDING_VERIFY) { done = true; return; }
  // Healthy = Wi-Fi up and the DNS service running for 60 s without a crash. Upstream
  // reachability is deliberately not required: an ISP outage must not roll back.
  if (WiFi.status() == WL_CONNECTED && gDns && gDns->running() && millis() > 60000) {
    esp_ota_mark_app_valid_cancel_rollback();
    gLog.log(hal::LogLevel::kInfo, "ota", "new firmware marked valid");
    done = true;
  } else if (millis() > 300000) {
    gLog.log(hal::LogLevel::kError, "ota", "new firmware unhealthy after 5 min: rolling back");
    esp_ota_mark_app_invalid_rollback_and_reboot();
  }
}

// Reconnects are automatic (WiFi.setAutoReconnect); if the network stays gone for
// 10 minutes, reboot (a never-configured device still gets the setup portal).
static void superviseWifi() {
  static uint32_t downSince = 0;
  if (WiFi.status() == WL_CONNECTED) {
    if (downSince) gLog.log(hal::LogLevel::kInfo, "wifi", "reconnected after %lu s", (millis() - downSince) / 1000);
    downSince = 0;
    return;
  }
  if (!downSince) { downSince = millis() | 1; gLog.log(hal::LogLevel::kWarn, "wifi", "disconnected"); }
  else if (millis() - downSince > 600000UL) { gLog.log(hal::LogLevel::kError, "wifi", "down for 10 min: rebooting"); delay(200); ESP.restart(); }
}

// The maintenance task is Arduino's loopTask (core 1, prio 1): give it room for TLS.
SET_LOOP_TASK_STACK_SIZE(16 * 1024);

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  if (!gKv.begin()) Serial.println("NVS FAILED");
  Serial.printf("PSRAM: %u KB free\n", (unsigned)(ESP.getFreePsram() / 1024));
  gBlocklist = new app::BlocklistManager(gFs, gHttp, gKv, gClock, gRandom, gLog, feedWatchdog);
  gBlocklist->begin();
  loadBanned();
  Serial.printf("blocklist: %u domains, banned: %d\n", (unsigned)gBlocklist->status().entries, numBanned);

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#else
  const int BOOT_PIN = 0;     // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin(HOSTNAME)) { MDNS.addService("http", "tcp", 80); Serial.printf("dashboard: http://%s.local\n", HOSTNAME); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  startDnsService();
  startTimeSync();
  pointResolverToSelf();
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { if (!requireAuth()) return; const bool ok = gBlocklist->addRule(false, web.arg("d")); web.send(ok ? 200 : 400, "text/plain", ok ? "ok" : "invalid domain"); });
  web.on("/unblock", []() { if (!requireAuth()) return; gBlocklist->removeRule(false, web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/allow", []() { if (!requireAuth()) return; const bool ok = gBlocklist->addRule(true, web.arg("d")); web.send(ok ? 200 : 400, "text/plain", ok ? "ok" : "invalid domain"); });
  web.on("/unallow", []() { if (!requireAuth()) return; gBlocklist->removeRule(true, web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    StateLock lock(gState);
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; { StateLock lock(gState); blockingOn = true; resumeAt = 0; } web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; gBlocklist->requestUpdate(); web.send(200, "text/plain", "update queued"); });
  web.on("/setupdate", []() {               // ?u=https://...  &t=HH:MM (daily, local time)
    if (!requireAuth()) return;
    if (web.hasArg("u") && !gBlocklist->setUrl(web.arg("u"))) { web.send(400, "text/plain", "URL must start with https://"); return; }
    if (web.hasArg("t")) {
      const String t = web.arg("t"); const int c = t.indexOf(':');
      if (c > 0) gBlocklist->setTime((uint8_t)t.substring(0, c).toInt(), (uint8_t)t.substring(c + 1).toInt());
    }
    web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname(HOSTNAME);      // pio run -t upload --upload-port <HOSTNAME>.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  xTaskCreatePinnedToCore(webTask, "web", 8192, nullptr, 3, nullptr, 0);
  WiFi.setAutoReconnect(true);
  Serial.println("DNS :53 (DoT/DoH upstream) + dashboard :80 + OTA up");
}

// Maintenance task: everything slow or periodic. Never touches DNS sockets.
void loop() {
  static bool watched = false;
  if (!watched) { esp_task_wdt_add(nullptr); watched = true; }
  esp_task_wdt_reset();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) {
    StateLock lock(gState);
    blockingOn = true; resumeAt = 0;
  }
  static uint32_t lastSlow = 0;
  if (millis() - lastSlow > 2000) {
    lastSlow = millis();
    resolvePendingMacs();
    superviseWifi();
    maintainOtaHealth();
  }
  static uint32_t lastResolverFix = 0;
  if (millis() - lastResolverFix > 60000) { lastResolverFix = millis(); pointResolverToSelf(); }
  gBlocklist->loop();                       // daily 02:00 IST update (feeds the watchdog itself)
  delay(50);
}
