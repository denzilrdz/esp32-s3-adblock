#include "web/portal.h"

#include <DNSServer.h>
#include <Preferences.h>
#include <WiFi.h>

#include "secrets.h"

namespace web {

namespace {

Preferences prefs;
DNSServer dnsPortal;
String portalOptions;  // <option> list of scanned networks
const char* portalHostname = "";

bool secretsConfigured() { return WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0; }

bool hasCredentials() {
  prefs.begin("wifi", true);
  const bool nvs = prefs.getString("ssid", "").length() > 0;
  prefs.end();
  return nvs || secretsConfigured();
}

const char kInput[] =
    "style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;"
    "border:1px solid #30363d;background:#161b22;color:#c9d1d9'";

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
  portalOptions = "";
  for (int i = 0; i < n && i < 15; i++) portalOptions += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
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
        "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>AdBlock setup</title>"
        "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;"
        "background:#0d1117;color:#c9d1d9'>"
        "<h2>&#128737; AdBlock &mdash; Wi-Fi setup</h2>"
        "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
        "<form method=POST action=/wifisave>"
        "<input list=nets name=s placeholder='Wi-Fi name' required ";
    html += kInput;
    html += "><datalist id=nets>" + portalOptions + "</datalist><input name=p type=password placeholder='Password' ";
    html += kInput;
    html +=
        "><button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;"
        "color:#000;font-weight:600;cursor:pointer'>Connect</button></form></body>";
    server.send(200, "text/html", html);
  };
  server.on("/", root);
  server.on("/wifisave", HTTP_POST, [&server]() {
    const String ss = server.arg("s"), pw = server.arg("p");
    if (!ss.length() || ss.length() > 32 || pw.length() > 64) {
      server.send(400, "text/plain", "invalid Wi-Fi name or password");
      return;
    }
    prefs.begin("wifi", false);
    prefs.putString("ssid", ss);
    prefs.putString("pass", pw);
    prefs.end();
    server.send(200, "text/html",
                "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                "&#9989; Saved. Restarting and joining <b>" +
                    htmlEscape(ss) + "</b>&hellip;<br><br>Reconnect your phone to your normal Wi-Fi, then open <b>" +
                    htmlEscape(portalHostname) + ".local</b>.</body>");
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
