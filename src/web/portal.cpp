#include "web/portal.h"

#include <DNSServer.h>
#include <Preferences.h>
#include <WiFi.h>

#include <memory>

#include "secrets.h"
#include "util/wifi_join.h"
#include "util/wifi_scan.h"

namespace web {

namespace {

Preferences prefs;
DNSServer dnsPortal;
String portalNetworks;  // radio list of scanned networks
const char* portalHostname = "";
// Last station disconnect reason (wifi_err_reason_t), set from the Wi-Fi event task.
volatile uint16_t lastDisconnectReason = 0;

bool secretsConfigured() {
  return WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0;
}

bool hasCredentials() {
  prefs.begin("wifi", true);
  const bool nvs = prefs.getString("ssid", "").length() > 0;
  prefs.end();
  return nvs || secretsConfigured();
}

// Setup pages (skill `web-ui`): phone-first, one column, 48 px tap targets, light and
// dark from the OS setting. They must work without JavaScript (iOS opens captive
// portals in a limited mini-browser): the network list is plain radio buttons.
const char kHead[] PROGMEM =
    "<!doctype html><html lang=en><meta charset=utf-8>"
    "<meta name=viewport content='width=device-width,initial-scale=1'><meta name=color-scheme content='light "
    "dark'>"
    "<title>AdBlock setup</title><style>"
    ":root{--page:#f6f6f4;--surface:#fcfcfb;--line:#e1e0d9;--axis:#c3c2b7;--ink:#0b0b0b;--ink2:#52514e;"
    "--muted:#76746e;--accent:#256abf;--accent-ink:#fff;--good:#0ca30c;--bad:#b42323;--sel:#e8f0fb}"
    "@media(prefers-color-scheme:dark){:root{--page:#0d0d0d;--surface:#1a1a19;--line:#2c2c2a;--axis:#4a4a46;"
    "--ink:#f0efec;--ink2:#c3c2b7;--muted:#9a988f;--accent:#3987e5;--accent-ink:#06121f;--bad:#f07070;--sel:#"
    "13202f}}"
    "*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);"
    "font:16px/1.45 system-ui,-apple-system,'Segoe UI',sans-serif}"
    "main{max-width:480px;margin:0 auto;padding:28px 16px 40px}"
    ".brand{display:flex;align-items:center;gap:8px;font-weight:650;font-size:18px}.brand "
    "svg{color:var(--good)}"
    "h1{font-size:22px;margin:18px 0 4px}p{color:var(--ink2);margin:0 0 18px}"
    ".card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:6px;margin:0 0 "
    "16px}"
    ".net{display:flex;align-items:center;gap:12px;min-height:52px;padding:8px 12px;border-radius:9px;"
    "cursor:pointer;width:100%;margin:0;border:0;background:none;color:var(--ink);font:inherit;"
    "font-weight:400;text-align:left;text-decoration:none}.net:hover{background:var(--sel)}"
    ".net+.net{border-top:1px solid var(--line);border-radius:0}.net i{color:var(--muted);font-style:normal}"
    ".net span{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.net "
    "svg{flex:none;color:var(--ink2)}"
    "label.f{display:block;font-size:14px;color:var(--ink2);margin:14px 0 6px}"
    "input.t{width:100%;min-height:48px;padding:10px 12px;border-radius:10px;border:1px solid var(--axis);"
    "background:var(--surface);color:var(--ink);font:inherit}"
    "input:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}"
    ".show{display:flex;align-items:center;gap:8px;font-size:14px;color:var(--ink2);margin:10px 0 0}"
    "button{width:100%;min-height:50px;margin-top:20px;border:0;border-radius:10px;background:var(--accent);"
    "color:var(--accent-ink);font:inherit;font-weight:650;cursor:pointer}"
    ".hint{font-size:13px;color:var(--muted)}ol{padding-left:22px;color:var(--ink2)}li{margin:6px 0}"
    "a{color:var(--accent)}.ok{color:var(--good)}.err{color:var(--bad)}input[readonly]{color:var(--ink2)}"
    ".warn{border-left:4px solid #fab219;background:var(--sel);border-radius:8px;padding:10px 12px;"
    "color:var(--ink)}"
    "</style><main><div class=brand><svg width=22 height=22 viewBox='0 0 24 24' aria-hidden=true>"
    "<path fill=currentColor d='M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Zm-1.2 13.6L7.4 "
    "12.2l1.4-1.4 "
    "2 2 4.4-4.4 1.4 1.4-5.8 5.8Z'/></svg>AdBlock</div>";

const char kLock[] =
    "<svg width=14 height=14 viewBox='0 0 24 24' role=img aria-label=secured><path fill=currentColor "
    "d='M17 9V7A5 5 0 0 0 7 7v2H5v13h14V9h-2Zm-8 0V7a3 3 0 0 1 6 0v2H9Z'/></svg>";

// Signal strength as four bars; the unlit ones are faint.
String bars(int rssi) {
  const int lit = util::signalBars(rssi);
  String svg =
      "<svg width=18 height=14 viewBox='0 0 18 14' role=img aria-label='signal " + String(lit) + " of 4'>";
  for (int i = 0; i < 4; i++) {
    const int h = 4 + i * 3;
    svg += "<rect x=" + String(i * 5) + " y=" + String(14 - h) + " width=3 height=" + String(h) +
           " rx=1 fill=currentColor" + (i < lit ? "" : " opacity=.25") + " />";
  }
  return svg + "</svg>";
}

void sendPage(WebServer& server, int code, const String& body) {
  server.send(code, "text/html", String(FPSTR(kHead)) + body + "</main></html>");
}

}  // namespace

String htmlEscape(const String& s) {
  String o;
  o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&': o += "&amp;"; break;
      case '<': o += "&lt;"; break;
      case '>': o += "&gt;"; break;
      case '"': o += "&quot;"; break;
      case '\'': o += "&#39;"; break;
      default: o += ch;
    }
  }
  return o;
}

bool connectWifi() {
  prefs.begin("wifi", true);
  const String ss = prefs.getString("ssid", "");
  const String pw = prefs.getString("pass", "");
  const bool joinedBefore = prefs.getBool("joined", false);
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || (!ss.length() && !secretsConfigured())) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);  // power save adds DNS latency
  WiFi.onEvent([](arduino_event_id_t,
                  arduino_event_info_t info) { lastDisconnectReason = info.wifi_sta_disconnected.reason; },
               ARDUINO_EVENT_WIFI_STA_DISCONNECTED);
  util::JoinRetryPolicy policy(joinedBefore);
  for (int attempt = 1;; attempt++) {
    lastDisconnectReason = 0;
    WiFi.begin(ssid, pass);
    const uint32_t t0 = millis(), limit = attempt == 1 ? 30000 : 15000;
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < limit) {
      delay(250);
      Serial.print(".");
    }
    Serial.println();
    if (WiFi.status() == WL_CONNECTED) {
      if (!joinedBefore) {  // from now on a missing network is waited for, not set up again
        prefs.begin("wifi", false);
        prefs.putBool("joined", true);
        prefs.end();
      }
      return true;
    }
    const uint16_t reason = lastDisconnectReason;
    if (policy.onFailure(util::classifyDisconnect(reason)) == util::JoinAction::kSetupPortal) return false;
    Serial.printf("WiFi: \"%s\" not joined (reason %u, attempt %d); retrying in 5 s\n", ssid, reason,
                  attempt);
    WiFi.disconnect();
    delay(5000);
  }
}

void forgetWifi() {
  prefs.begin("wifi", false);
  prefs.clear();
  prefs.end();
}

namespace {

util::WifiSecurity securityOf(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN:
    case WIFI_AUTH_OWE: return util::WifiSecurity::kOpen;
    case WIFI_AUTH_WPA_PSK:
    case WIFI_AUTH_WPA2_PSK:
    case WIFI_AUTH_WPA_WPA2_PSK:
    case WIFI_AUTH_WPA3_PSK:
    case WIFI_AUTH_WPA2_WPA3_PSK:
    case WIFI_AUTH_WAPI_PSK:
    case WIFI_AUTH_WPA3_EXT_PSK:
    case WIFI_AUTH_WPA3_EXT_PSK_MIXED_MODE: return util::WifiSecurity::kPsk;
    default: return util::WifiSecurity::kOther;  // WEP, enterprise, DPP
  }
}

// Step 2: the chosen network's name (filled in, or typed for "Other") and its password.
String joinPage(const String& ssid, util::WifiSecurity sec, bool listed, const char* error) {
  using util::WifiSecurity;
  const String name = htmlEscape(ssid);
  String h = "<p><a href=/>&lsaquo; All networks</a></p><h1>";
  h += listed ? "Join &ldquo;" + name + "&rdquo;" : String("Other network");
  h += "</h1>";
  if (error) h += "<p class=warn>" + String(error) + "</p>";
  h += "<form method=POST action=/wifisave><label class=f for=s>Network name</label>";
  if (listed)
    h += "<input class=t id=s name=s value='" + name + "' readonly>";
  else
    h += "<input class=t id=s name=s value='" + name +
         "' required maxlength=32 autocapitalize=off autocomplete=off spellcheck=false" +
         (error ? "" : " autofocus") + ">";
  if (sec == WifiSecurity::kOpen) {
    h += "<p class=hint style='margin:10px 0 0'>Open network: no password needed.</p>";
  } else {
    h += "<label class=f for=p>Password</label><input class=t id=p name=p type=password maxlength=64 "
         "autocomplete=current-password";
    if (sec == WifiSecurity::kPsk) h += " required minlength=8";
    if (sec == WifiSecurity::kOther) h += " required";
    if (sec == WifiSecurity::kUnknown) h += " minlength=8";
    if (listed || error) h += " autofocus";
    h += "><p class=hint style='margin:6px 0 0'>";
    h += sec == WifiSecurity::kUnknown ? "Leave empty for an open network; otherwise 8 or more characters."
                                       : "The Wi-Fi password, 8 or more characters.";
    h += "</p><label class=show><input type=checkbox onchange=\"p.type=this.checked?'text':'password'\">"
         "Show password</label>";
  }
  return h + "<button>Connect</button></form>";
}

}  // namespace

[[noreturn]] void runSetupPortal(WebServer& server, const char* apPrefix, const char* hostname) {
  using util::WifiSecurity;
  portalHostname = hostname;
  // Shown when a saved network didn't join (wrong password, out of range).
  String lastSsid;
  if (hasCredentials()) {
    prefs.begin("wifi", true);
    lastSsid = prefs.getString("ssid", "");
    prefs.end();
    if (!lastSsid.length()) lastSsid = WIFI_SSID;
  }
  // Scan while still in STA mode. After a failed join the station is still retrying the
  // saved network, and a scan then fails (returns < 0) and the list came up empty
  // (found on hardware): stop the attempt first, and retry a failed scan.
  WiFi.setAutoReconnect(false);
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks();
  for (int attempt = 1; n < 0 && attempt < 3; attempt++) {
    delay(500);
    n = WiFi.scanNetworks();
  }
  Serial.printf("[setup] Wi-Fi scan: %d network%s\n", n < 0 ? 0 : n, n == 1 ? "" : "s");
  // Setup mode only (this function never returns): the listed networks and their
  // security, so the next step asks for the right password.
  constexpr size_t kScanMax = 30, kShowMax = 15;
  std::unique_ptr<util::ScanEntry[]> picked(new util::ScanEntry[kShowMax]);
  size_t shown = 0;
  {
    std::unique_ptr<util::ScanEntry[]> scanned(new util::ScanEntry[kScanMax]);
    size_t count = 0;
    for (int i = 0; i < n && count < kScanMax; i++, count++) {
      strncpy(scanned[count].ssid, WiFi.SSID(i).c_str(), util::kMaxSsidLength);
      scanned[count].ssid[util::kMaxSsidLength] = 0;
      scanned[count].rssi = WiFi.RSSI(i);
      scanned[count].security = securityOf(WiFi.encryptionType(i));
    }
    WiFi.scanDelete();
    shown = util::pickNetworks(scanned.get(), count, picked.get(), kShowMax);
  }
  portalNetworks = "";
  for (size_t i = 0; i < shown; i++) {
    const String name = htmlEscape(picked[i].ssid);
    portalNetworks += "<button class=net name=s value='" + name + "'><span>" + name + "</span>" +
                      (picked[i].security != WifiSecurity::kOpen ? kLock : "") + bars(picked[i].rssi) +
                      "<i aria-hidden=true>&rsaquo;</i></button>";
  }
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char ap[32];
  snprintf(ap, sizeof(ap), "%s-%02X%02X", apPrefix, mac[4], mac[5]);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(ap);
  const IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);  // catch-all -> phones pop the captive portal

  // A listed network, or nullptr for one typed by hand.
  auto find = [&picked, &shown](const String& ssid) -> const util::ScanEntry* {
    for (size_t i = 0; i < shown; i++)
      if (ssid == picked[i].ssid) return &picked[i];
    return nullptr;
  };
  // Step 1: tap a network (plain buttons and links: works without JavaScript).
  auto root = [&server, &lastSsid]() {
    String html = "<h1>Connect to Wi-Fi</h1>";
    if (lastSsid.length()) {
      const String name = htmlEscape(lastSsid);
      html += "<p class=warn>Couldn't join <b>" + name +
              "</b>. Check the password, or pick another network.</p>"
              // One tap back to its password page (name filled in), listed or not.
              "<form action=/join><div class=card><button class=net name=s value='" +
              name + "'><span>Re-enter the password for " + name +
              "</span><i aria-hidden=true>&rsaquo;</i></button></div></form>";
    }
    html += "<p>Tap your home network. The blocker restarts and joins it.</p>";
    if (portalNetworks.length())
      html += "<form action=/join><div class=card>" + portalNetworks + "</div></form>";
    else
      html += "<p class=warn>No networks found. Move closer to the router, or enter the name by hand.</p>";
    html +=
        "<div class=card><a class=net href=/join><span>Other network&hellip;</span><i "
        "aria-hidden=true>&rsaquo;</i></a></div>"
        "<p class=hint>Only 2.4 GHz networks work. Hidden network? Use Other.</p>";
    sendPage(server, 200, html);
  };
  server.on("/", root);
  server.on("/join", HTTP_GET, [&server, &find]() {
    const String ss = server.arg("s");
    const util::ScanEntry* e = ss.length() ? find(ss) : nullptr;
    sendPage(server, 200, joinPage(ss, e ? e->security : WifiSecurity::kUnknown, e != nullptr, nullptr));
  });
  server.on("/wifisave", HTTP_POST, [&server, &find]() {
    const String ss = server.arg("s");
    String pw = server.arg("p");
    const util::ScanEntry* e = find(ss);
    const WifiSecurity sec = e ? e->security : WifiSecurity::kUnknown;
    const char* error = nullptr;
    switch (util::checkCredentials(ss.length(), pw.c_str(), pw.length(), sec)) {
      case util::CredentialCheck::kOk: break;
      case util::CredentialCheck::kBadName: error = "Enter the network name (up to 32 characters)."; break;
      case util::CredentialCheck::kNeedPassword: error = "This network needs its password."; break;
      case util::CredentialCheck::kBadPassword:
        error = "Wi-Fi passwords are 8 to 63 characters (or a 64-digit hex key).";
        break;
    }
    if (error) {  // nothing saved: ask again, keeping the name
      sendPage(server, 400, joinPage(ss, sec, e != nullptr, error));
      return;
    }
    if (sec == WifiSecurity::kOpen) pw = "";
    prefs.begin("wifi", false);
    prefs.putString("ssid", ss);
    prefs.putString("pass", pw);
    prefs.putBool("joined", false);  // new credentials: a failed join opens setup again
    prefs.end();
    sendPage(
        server, 200,
        "<h1 class=ok>&#10003; Saved</h1><p>Restarting and joining <b>" + htmlEscape(ss) +
            "</b>&hellip;</p><ol><li>Reconnect this phone to your normal Wi-Fi.</li><li>Open <b>http://" +
            htmlEscape(portalHostname) +
            ".local</b> (or the device's IP from your router) for the dashboard.</li>"
            "<li>Point your router's DNS at the device.</li></ol><p class=hint>Wrong password? After "
            "about 30 seconds this setup network appears again so you can retry.</p>");
    delay(900);
    ESP.restart();
  });
  server.onNotFound(root);  // any captive-portal probe -> the form
  server.begin();
  Serial.printf("\n[setup] No Wi-Fi. Join open network \"%s\" and a setup page pops up (or http://%s)\n", ap,
                apIP.toString().c_str());
  const bool configured = hasCredentials();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest();
    server.handleClient();
    delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();  // someone is setting it up
    if (configured && millis() - t0 > 180000UL) {
      Serial.println("[setup] retrying Wi-Fi");
      ESP.restart();
    }
  }
}

}  // namespace web
