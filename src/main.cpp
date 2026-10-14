// ESP32-S3 AdBlock — Pi-hole-style DNS sinkhole for the ESP32-S3 (fork of
// M-Abozaid/esp32-c3-adblock). This file is the composition root: it creates the
// platform services, wires dependencies and starts the tasks. Logic lives in
// lib/core (portable, unit-tested) and src/{app,platform,tasks,web}.
// Design: docs/ARCHITECTURE.md.

#include <Arduino.h>
#include <ArduinoOTA.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <WebServer.h>
#include <WiFi.h>
#include <esp_netif.h>
#include <esp_ota_ops.h>
#include <esp_sntp.h>
#include <esp_task_wdt.h>

#include "app/app_policy.h"
#include "app/blocklist_manager.h"
#include "app/clients.h"
#include "auth/auth.h"
#include "config/config.h"
#include "platform/esp_clock.h"
#include "platform/esp_http.h"
#include "platform/esp_random.h"
#include "platform/littlefs_fs.h"
#include "platform/nvs_kv_store.h"
#include "platform/psram.h"
#include "platform/serial_logger.h"
#include "platform/transports.h"
#include "secrets.h"  // first-boot defaults only (copy secrets.example.h); gitignored
#include "tasks/dns_service.h"
#include "web/dashboard.h"
#include "web/portal.h"

#ifndef FW_VERSION
#define FW_VERSION "0.0.0-dev"
#endif

namespace {

#if CONFIG_IDF_TARGET_ESP32S3
const char* kHostname = "s3adblock";
const char* kApPrefix = "S3-AdBlock";
#else
const char* kHostname = "c3adblock";
const char* kApPrefix = "C3-AdBlock";
#endif
const char* kOtaPlaceholder = "CHANGE_ME_OTA_PASSWORD";

// ---- platform services (long-lived singletons) ----
platform::EspClock gClock;
platform::EspRandom gRandom;
platform::SerialLogger gLog;
platform::LittleFsFileSystem gFs;
platform::NvsKvStore gKv("adblock");
platform::EspHttpClient gHttp;
WebServer gServer(80);

// ---- application objects (created in setup(), never destroyed) ----
config::AppConfig gConfig;
app::ClientTable gClients;
app::BlocklistManager* gBlocklist = nullptr;
app::AppPolicy* gPolicy = nullptr;
app::DnsService* gDns = nullptr;
auth::PasswordStore* gPasswords = nullptr;
auth::LoginGuard gLogins(gClock);
web::Dashboard* gDashboard = nullptr;

void feedWatchdog() {
  esp_task_wdt_reset();
}

void applyLiveConfig(const config::AppConfig& c) {
  setenv("TZ", c.timezone, 1);
  tzset();
  gLog.setLevel(static_cast<hal::LogLevel>(c.logLevel));
}

// Wall clock: SNTP via hard-coded Cloudflare time IPs (no DNS needed) plus the pool.
// Nothing time-of-day based (the 02:00 update) runs until the first sync.
void startTimeSync() {
  sntp_set_time_sync_notification_cb([](struct timeval*) {
    if (!gClock.wallClockSynced()) gLog.log(hal::LogLevel::kInfo, "time", "clock synced");
    gClock.setSynced(true);
  });
  static char tz[sizeof(gConfig.timezone)];
  snprintf(tz, sizeof(tz), "%s", gConfig.timezone);  // configTzTime keeps the pointer
  configTzTime(tz, "162.159.200.1", "162.159.200.123", "pool.ntp.org");
}

// The device's own lookups (blocklist host, NTP pool) go through our own DNS service
// on 127.0.0.1, so they are encrypted too. DHCP renewals overwrite the resolver, so
// this is re-applied periodically.
void pointResolverToSelf() {
  esp_netif_t* nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (!nif) return;
  esp_netif_dns_info_t dns = {};
  dns.ip.type = ESP_IPADDR_TYPE_V4;
  dns.ip.u_addr.ip4.addr = ESP_IP4TOADDR(127, 0, 0, 1);
  esp_netif_set_dns_info(nif, ESP_NETIF_DNS_MAIN, &dns);
}

// Upstream chain from the settings (ARCHITECTURE.md §7.1): DoT, then DoH, then plain.
void startDnsService() {
  static config::Endpoint endpoints[upstream::Forwarder::kMaxUpstreams];
  static upstream::ITransport* chain[upstream::Forwarder::kMaxUpstreams];
  const size_t n = config::buildChain(gConfig, endpoints, upstream::Forwarder::kMaxUpstreams);
  for (size_t i = 0; i < n; i++) {
    const config::Endpoint& e = endpoints[i];
    switch (e.kind) {
      case upstream::TransportKind::kDoT:
        chain[i] = new platform::DotTransport(e.name, e.ip, e.verifyName, e.port);
        break;
      case upstream::TransportKind::kDoH:
        chain[i] = new platform::DohTransport(e.name, e.ip, e.verifyName, "/dns-query", e.port);
        break;
      case upstream::TransportKind::kUdp: chain[i] = new platform::UdpTransport(e.name, e.ip, e.port); break;
    }
  }
  app::DnsServiceConfig cfg;
  cfg.blockedTtl = gConfig.blockedTtl;
  cfg.passAd = gConfig.passAd;
  cfg.local.firefoxCanary = gConfig.firefoxCanary;
  cfg.local.icloudPrivateRelay = gConfig.icloudRelay;
  cfg.local.privateReverse = gConfig.privateReverse;
  cfg.forwarder.allowPlainFallback = gConfig.plainFallback;
  cfg.forwarder.query.padding = gConfig.padding;
  cfg.forwarder.query.requestAd = gConfig.passAd;
  if (!platform::havePsram()) {  // lite profile (C3 / classic ESP32): small cache, UDP only
    cfg.cache.maxEntries = 512;
    cfg.cache.arenaBytes = 64 * 1024;
    cfg.pendingSlots = 16;
    cfg.tcpEnabled = false;
    cfg.replyCap = dns::kMaxUdpPayload;
  }
  gDns = new app::DnsService(cfg, *gPolicy, gClock, gRandom, gLog, chain, n);
  if (!gDns->start()) gLog.log(hal::LogLevel::kError, "boot", "DNS service failed to start");
}

// web task (core 0, prio 3): dashboard + ArduinoOTA, so a slow HTTP client or a
// blocklist download in the maintenance task never stalls the other.
void webTask(void*) {
  esp_task_wdt_add(nullptr);
  while (true) {
    gServer.handleClient();
    ArduinoOTA.handle();
    esp_task_wdt_reset();
    vTaskDelay(pdMS_TO_TICKS(2));
  }
}

void startOta() {
  if (!OTA_PASS || strlen(OTA_PASS) < 10 || strcmp(OTA_PASS, kOtaPlaceholder) == 0) {
    gLog.log(hal::LogLevel::kWarn, "ota",
             "network OTA disabled: set a real OTA_PASS (10+ chars) in secrets.h");
    return;
  }
  ArduinoOTA.setHostname(kHostname);  // pio run -t upload --upload-port <hostname>.local
  ArduinoOTA.setPassword(OTA_PASS);
  ArduinoOTA.begin();
}

void maintainOtaHealth() {
  static bool done = false;
  if (done) return;
  esp_ota_img_states_t state;
  if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &state) != ESP_OK ||
      state != ESP_OTA_IMG_PENDING_VERIFY) {
    done = true;
    return;
  }
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

// Reconnects are automatic (WiFi.setAutoReconnect); if the network stays gone for 10
// minutes, reboot (a never-configured device still gets the setup portal).
void superviseWifi() {
  static uint32_t downSince = 0;
  if (WiFi.status() == WL_CONNECTED) {
    if (downSince)
      gLog.log(hal::LogLevel::kInfo, "wifi", "reconnected after %lu s", (millis() - downSince) / 1000);
    downSince = 0;
    return;
  }
  if (!downSince) {
    downSince = millis() | 1;
    gLog.log(hal::LogLevel::kWarn, "wifi", "disconnected");
  } else if (millis() - downSince > 600000UL) {
    gLog.log(hal::LogLevel::kError, "wifi", "down for 10 min: rebooting");
    delay(200);
    ESP.restart();
  }
}

void clearWifiIfBootHeld() {
#if CONFIG_IDF_TARGET_ESP32C3
  const int bootPin = 9;  // C3 BOOT button
#else
  const int bootPin = 0;  // ESP32 / ESP32-S3 BOOT button
#endif
  pinMode(bootPin, INPUT_PULLUP);
  if (digitalRead(bootPin) == LOW) {
    delay(60);
    if (digitalRead(bootPin) == LOW) {
      web::forgetWifi();
      Serial.println("[setup] BOOT held -> cleared saved Wi-Fi");
    }
  }
}

}  // namespace

// Firmware rollback: Arduino would mark a freshly OTA-flashed image valid at boot. We
// defer that until the new firmware has proved healthy (maintainOtaHealth()).
extern "C" bool verifyRollbackLater() {
  return true;
}  // overrides a weak C symbol

// The maintenance task is Arduino's loopTask (core 1, prio 1): give it room for TLS.
SET_LOOP_TASK_STACK_SIZE(16 * 1024);

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.printf("\n[adblock] v%s booting (%s, PSRAM %u KB)\n", FW_VERSION, kHostname,
                static_cast<unsigned>(ESP.getPsramSize() / 1024));
  if (!LittleFS.begin(true)) Serial.println("[ERROR] LittleFS failed");
  if (!gKv.begin()) Serial.println("[ERROR] NVS failed");
  config::load(gKv, gConfig);
  applyLiveConfig(gConfig);

  gPasswords = new auth::PasswordStore(gKv, gRandom, WEB_USER, WEB_PASS);
  if (gPasswords->mustChange())
    Serial.printf("[setup] Dashboard password not set. One-time setup code: %s  (user: %s)\n",
                  gPasswords->setupCode(), gPasswords->user());

  gBlocklist = new app::BlocklistManager(gFs, gHttp, gKv, gClock, gRandom, gLog, feedWatchdog);
  gBlocklist->begin();
  gClients.loadBans();
  gPolicy = new app::AppPolicy(gClients, *gBlocklist);

  clearWifiIfBootHeld();
  if (!web::connectWifi()) web::runSetupPortal(gServer, kApPrefix, kHostname);  // reboots when done
  Serial.printf("Wi-Fi up: %s\n", WiFi.localIP().toString().c_str());
  WiFi.setAutoReconnect(true);
  if (MDNS.begin(kHostname)) MDNS.addService("http", "tcp", 80);

  startDnsService();
  startTimeSync();
  pointResolverToSelf();

  web::DashboardContext ctx;
  ctx.server = &gServer;
  ctx.clients = &gClients;
  ctx.blocklist = gBlocklist;
  ctx.dns = gDns;
  ctx.passwords = gPasswords;
  ctx.logins = &gLogins;
  ctx.config = &gConfig;
  ctx.kv = &gKv;
  ctx.log = &gLog;
  ctx.hostname = kHostname;
  ctx.version = FW_VERSION;
  ctx.applyLive = applyLiveConfig;
  gDashboard = new web::Dashboard(ctx);
  gDashboard->begin();
  gServer.begin();
  startOta();
  xTaskCreatePinnedToCore(webTask, "web", 8192, nullptr, 3, nullptr, 0);
  gLog.log(hal::LogLevel::kInfo, "boot", "ready: DNS :53, dashboard http://%s.local", kHostname);
}

// Maintenance task: everything slow or periodic. Never touches DNS sockets.
void loop() {
  static bool watched = false;
  if (!watched) {
    esp_task_wdt_add(nullptr);
    watched = true;
  }
  esp_task_wdt_reset();
  gClients.tick();
  static uint32_t lastSlow = 0;
  if (millis() - lastSlow > 2000) {
    lastSlow = millis();
    gClients.resolvePendingMacs();
    superviseWifi();
    maintainOtaHealth();
  }
  static uint32_t lastResolverFix = 0;
  if (millis() - lastResolverFix > 60000) {
    lastResolverFix = millis();
    pointResolverToSelf();
  }
  gBlocklist->loop();  // daily update (feeds the watchdog itself)
  delay(50);
}
