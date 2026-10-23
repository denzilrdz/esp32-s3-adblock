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
#include <esp_rom_sys.h>
#include <esp_sntp.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>

#include "app/app_policy.h"
#include "app/blocklist_manager.h"
#include "app/clients.h"
#include "auth/auth.h"
#include "config/config.h"
#include "diag/liveness.h"
#include "platform/esp_clock.h"
#include "platform/esp_http.h"
#include "platform/esp_random.h"
#include "platform/littlefs_fs.h"
#include "platform/nvs_kv_store.h"
#include "platform/psram.h"
#include "platform/restart_info.h"
#include "platform/serial_logger.h"
#include "platform/transports.h"
#include "platform/watchdog.h"
#include "secrets.h"  // first-boot defaults only (copy secrets.example.h); gitignored
#include "tasks/dns_service.h"
#include "web/dashboard.h"
#include "web/portal.h"

#ifndef FW_VERSION
#define FW_VERSION "0.0.0-dev"
#endif

namespace {

const char* kHostname = "s3adblock";
const char* kApPrefix = "S3-AdBlock";
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
auth::SessionStore gSessions(gClock, gRandom);
web::Dashboard* gDashboard = nullptr;
diag::RestartInfo gRestart;

// Software watchdog (lib/core/diag/liveness.h) for what the 5 s hardware one can't
// cover. Limits: the web task's library-bounded waits are seconds, its slowest
// legitimate call (a firmware upload) beats per chunk; a whole blocklist download
// takes seconds (5 min overall deadline in esp_http.cpp, this is the backstop); one
// upstream-task loop is bounded by ForwarderConfig::maxBlockingMs (4 s).
diag::LivenessMonitor gLiveness(gClock);
int gWebAlive = -1;
int gDownloadAlive = -1;
int gUpstreamAlive = -1;
// Web: 10 min. Every slow-client case is bounded well below that (2 s per header line,
// 4 s per request, ~10 s without send progress, 20 s per page), except a client
// trickling a request body on purpose; this only catches a real hang (ARCHITECTURE §9).
#ifndef ADBLOCK_SELFTEST
constexpr uint32_t kWebStuckMs = 600000;
constexpr uint32_t kDownloadStuckMs = 360000;
constexpr uint32_t kUpstreamStuckMs = 30000;
#else  // short limits so each self-test hang ends within seconds
constexpr uint32_t kWebStuckMs = 20000;
constexpr uint32_t kDownloadStuckMs = 20000;
constexpr uint32_t kUpstreamStuckMs = 10000;
#endif
constexpr uint32_t kLivenessPeriodMs = 5000;
constexpr uint32_t kCheckerStalledMs = 30000;  // the timer that runs check() stopped
bool gLivenessRunning = false;                 // the timer started; judge it from now on
esp_timer_handle_t gLivenessTimer = nullptr;

#ifdef ADBLOCK_SELFTEST
// Self-test hangs (env esp32s3_selftest, skill debugging). Each must end in a restart
// whose reason names the hang: software watchdog ("<activity> stuck", "software
// watchdog stopped") or hardware watchdog (crash record).
std::atomic<int> gSelftestUpstream{0};
std::atomic<bool> gSelftestDownload{false};

void selftestSpin(void*) {
  while (true) {  // never yields: starves IDLE0
  }
}

void selftest(const String& what) {
  esp_rom_printf("[W][selftest] hang %s\n", what.c_str());
  if (what == "web") {
    while (true) vTaskDelay(pdMS_TO_TICKS(100));  // the web task stops making progress
  } else if (what == "download") {
    gSelftestDownload.store(true);  // loop() hangs as if inside esp_http_client
  } else if (what == "upstream") {
    gSelftestUpstream.store(1);
  } else if (what == "upstream-hw") {
    gSelftestUpstream.store(2);
  } else if (what == "checker") {
    esp_timer_stop(gLivenessTimer);
  } else if (what == "idle0") {
    xTaskCreatePinnedToCore(selftestSpin, "selftest_spin", 2048, nullptr, 5, nullptr, 0);
  }
}
#endif

void feedWatchdog() {
  platform::feedWatchdog();  // also called from setup(), before loop() subscribes
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
  cfg.liveness = &gLiveness;
  cfg.livenessId = gUpstreamAlive;
#ifdef ADBLOCK_SELFTEST
  cfg.selftestHang = &gSelftestUpstream;
#endif
  gDns = new app::DnsService(cfg, *gPolicy, gClock, gRandom, gLog, chain, n);
  if (gDns->start())
    gLiveness.arm(gUpstreamAlive);  // dns_up beats from its first loop on
  else
    gLog.log(hal::LogLevel::kError, "boot", "DNS service failed to start");
}

// web task (core 0): dashboard + ArduinoOTA, so a slow HTTP client or a blocklist
// download in the maintenance task never stalls the other.
//
// It runs at idle priority and is NOT on the task watchdog. Arduino's WebServer
// busy-waits with yield() while a request trickles in (up to WEBSERVER_MAX_LINE_WAIT
// per line, WEBSERVER_MAX_HEADER_WAIT per request) and retries a blocked send for up
// to ~10 s. At priority 3 that starved IDLE0, and the 5 s watchdog restarted the board
// whenever one phone's Wi-Fi hiccuped mid-request (reproduced 2026-10-23 with one
// client trickling headers). Those waits are bounded by the library; a web task stuck
// for good is caught by the software watchdog (gWebAlive, kWebStuckMs).
void webTask(void*) {
  gLiveness.arm(gWebAlive);
  while (true) {
    gLiveness.beat(gWebAlive);
    gServer.handleClient();
    ArduinoOTA.handle();
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
  ArduinoOTA.onEnd([]() { platform::noteRestart("firmware update (ArduinoOTA)"); });  // it reboots itself
  ArduinoOTA.onProgress([](unsigned, unsigned) { gLiveness.beat(gWebAlive); });       // runs in the web task
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
    platform::noteRestart("rollback: new firmware unhealthy");
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
    platform::restart("Wi-Fi down for 10 min");
  }
}

void clearWifiIfBootHeld() {
  const int bootPin = 0;  // ESP32-S3 BOOT button
  pinMode(bootPin, INPUT_PULLUP);
  if (digitalRead(bootPin) == LOW) {
    delay(60);
    if (digitalRead(bootPin) == LOW) {
      web::forgetWifi();
      Serial.println("[setup] BOOT held -> cleared saved Wi-Fi");
    }
  }
}

// Runs every kLivenessPeriodMs in the esp_timer task, independent of the tasks it
// watches (the maintenance task may be inside a download with its watchdog paused).
void livenessCheck(void*) {
  const char* stuck = gLiveness.check();
  if (!stuck) return;
  char why[sizeof(diag::RestartInfo::note)];
  snprintf(why, sizeof(why), "%s stuck", stuck);
  // ROM printf, not gLog: the stuck task may hold the logger's mutex, and blocking on
  // it here would leave nothing to restart the board. The reason survives in RTC memory.
  esp_rom_printf("[E][boot] %s: rebooting\n", why);
  platform::restart(why);
}

void startLivenessChecks() {
  gLiveness.check();  // first run before loop() starts judging the checker
  esp_timer_create_args_t args = {};
  args.callback = livenessCheck;
  args.name = "liveness";
  gLivenessRunning =
      esp_timer_create(&args, &gLivenessTimer) == ESP_OK &&
      esp_timer_start_periodic(gLivenessTimer, static_cast<uint64_t>(kLivenessPeriodMs) * 1000) == ESP_OK;
  if (!gLivenessRunning) gLog.log(hal::LogLevel::kError, "boot", "software watchdog could not start");
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
  gRestart = platform::readRestartInfo();
  // Armed only once each task runs: setup() may wait minutes for Wi-Fi first.
  gWebAlive = gLiveness.add("web task", kWebStuckMs, false);
  gDownloadAlive = gLiveness.add("blocklist download", kDownloadStuckMs, false);  // armed by get()
  gUpstreamAlive = gLiveness.add("upstream task", kUpstreamStuckMs, false);
  gHttp.setLiveness(&gLiveness, gDownloadAlive);
  {
    char why[160], bt[200];
    diag::describe(gRestart, why, sizeof(why));
    Serial.printf("[boot] last restart: %s\n", why);
    if (gRestart.crash.present) {
      diag::formatBacktrace(gRestart.crash, bt, sizeof(bt));
      Serial.printf("[boot] crash record (%s): task %s, %s; backtrace %s%s\n",
                    gRestart.crashThisBoot() ? "this restart" : "earlier", gRestart.crash.task,
                    gRestart.crash.reason[0] ? gRestart.crash.reason : "no reason", bt,
                    gRestart.crash.corrupted ? " (corrupted)" : "");
    }
  }
  if (!platform::havePsram())
    Serial.println(
        "[ERROR] No PSRAM found. This firmware needs an ESP32-S3 with octal PSRAM (N16R8); "
        "check board_build.arduino.memory_type = qio_opi. DNS will not start.");
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
  ctx.sessions = &gSessions;
  ctx.restart = &gRestart;
  ctx.alive = []() { gLiveness.beat(gWebAlive); };
  ctx.clock = &gClock;
#ifdef ADBLOCK_SELFTEST
  ctx.selftest = selftest;
#endif
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
  xTaskCreatePinnedToCore(webTask, "web", 8192, nullptr, tskIDLE_PRIORITY, nullptr, 0);
  startLivenessChecks();
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
    if (gLivenessRunning && gLiveness.checkerStalled(kCheckerStalledMs)) {  // who watches the watchdog
      gLog.log(hal::LogLevel::kError, "boot", "software watchdog stopped running: rebooting");
      delay(200);
      platform::restart("software watchdog stopped");
    }
  }
  static uint32_t lastResolverFix = 0;
  if (millis() - lastResolverFix > 60000) {
    lastResolverFix = millis();
    pointResolverToSelf();
  }
  gBlocklist->loop();  // daily update (feeds the watchdog itself)
#ifdef ADBLOCK_SELFTEST
  if (gSelftestDownload.load()) {  // what EspHttpClient::get() does around a stuck open()
    platform::WatchdogPause noWatchdog;
    gLiveness.arm(gDownloadAlive);
    while (true) vTaskDelay(pdMS_TO_TICKS(100));
  }
#endif
  delay(50);
}
