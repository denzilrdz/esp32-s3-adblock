#include "web/portal.h"

#include <DNSServer.h>
#include <Preferences.h>
#include <WiFi.h>

#include "secrets.h"
#include "util/wifi_scan.h"

namespace web {

namespace {

Preferences prefs;
DNSServer dnsPortal;
String portalNetworks;  // radio list of scanned networks
const char* portalHostname = "";

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
    ".net{display:flex;align-items:center;gap:12px;min-height:52px;padding:8px "
    "12px;border-radius:9px;cursor:pointer}"
    ".net+.net{border-top:1px solid var(--line)}.net:has(input:checked){background:var(--sel)}"
    ".net input{width:20px;height:20px;margin:0;accent-color:var(--accent);flex:none}"
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
    "a{color:var(--accent)}.ok{color:var(--good)}.err{color:var(--bad)}"
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
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || (!ss.length() && !secretsConfigured())) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);  // power save adds DNS latency
  WiFi.begin(ssid, pass);
  const uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) {
    delay(250);
    Serial.print(".");
  }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

void forgetWifi() {
  prefs.begin("wifi", false);
  prefs.clear();
  prefs.end();
}

[[noreturn]] void runSetupPortal(WebServer& server, const char* apPrefix, const char* hostname) {
  portalHostname = hostname;
  const int n = WiFi.scanNetworks();  // scan while still in STA mode
  static util::ScanEntry scanned[30], picked[15];
  size_t count = 0;
  for (int i = 0; i < n && count < 30; i++, count++) {
    strncpy(scanned[count].ssid, WiFi.SSID(i).c_str(), util::kMaxSsidLength);
    scanned[count].ssid[util::kMaxSsidLength] = 0;
    scanned[count].rssi = WiFi.RSSI(i);
    scanned[count].secured = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
  }
  WiFi.scanDelete();
  const size_t shown = util::pickNetworks(scanned, count, picked, 15);
  portalNetworks = "";
  for (size_t i = 0; i < shown; i++) {
    const String name = htmlEscape(picked[i].ssid);
    portalNetworks += "<label class=net><input type=radio name=s value='" + name + "' required" +
                      (i ? "" : " checked") + "><span>" + name + "</span>" +
                      (picked[i].secured ? kLock : "") + bars(picked[i].rssi) + "</label>";
  }
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char ap[32];
  snprintf(ap, sizeof(ap), "%s-%02X%02X", apPrefix, mac[4], mac[5]);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(ap);
  const IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);  // catch-all -> phones pop the captive portal

  auto root = [&server]() {
    String html =
        "<h1>Connect to Wi-Fi</h1><p>Pick your home network and enter its password. The blocker restarts "
        "and joins it.</p><form method=POST action=/wifisave><div class=card>";
    html += portalNetworks;
    html += "<label class=net><input type=radio name=s value=''";
    html += portalNetworks.length() ? "" : " checked";
    html +=
        "><span>Other network&hellip;</span></label></div>"
        "<label class=f for=o>Network name <span class=hint>(only for &ldquo;Other&rdquo;)</span></label>"
        "<input class=t id=o name=o maxlength=32 autocapitalize=off autocomplete=off spellcheck=false>"
        "<label class=f for=p>Password</label>"
        "<input class=t id=p name=p type=password maxlength=64 autocomplete=current-password>"
        "<label class=show><input type=checkbox onchange=\"p.type=this.checked?'text':'password'\">"
        "Show password</label><button>Connect</button></form>"
        "<p class=hint style=margin-top:18px>Not listed? Move closer to the router, or choose Other and type "
        "the name. Only 2.4 GHz networks work.</p>";
    sendPage(server, 200, html);
  };
  server.on("/", root);
  server.on("/wifisave", HTTP_POST, [&server]() {
    String ss = server.arg("s");
    if (!ss.length()) ss = server.arg("o");  // "Other network"
    const String pw = server.arg("p");
    if (!ss.length() || ss.length() > 32 || pw.length() > 64) {
      sendPage(server, 400,
               "<h1 class=err>Check the network name</h1><p>Pick a network, or choose Other and type its "
               "name (up to 32 characters). Passwords are up to 64 characters.</p><a href=/>Back</a>");
      return;
    }
    prefs.begin("wifi", false);
    prefs.putString("ssid", ss);
    prefs.putString("pass", pw);
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
