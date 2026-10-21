#pragma once
// Wi-Fi provisioning: connect with saved (NVS) or secrets.h credentials, or run the
// open setup access point with a captive portal (upstream esp32-c3-adblock flow).

#include <WebServer.h>

namespace web {

// Tries NVS credentials, then secrets.h. Credentials that have never joined give up
// after 30 s (false -> setup portal). Once they have joined, a missing network (router
// off or booting) is retried every 5 s until it appears; only repeated password
// rejections give up.
bool connectWifi();
// Clears saved Wi-Fi credentials (BOOT held at power-on, or dashboard "Forget Wi-Fi").
void forgetWifi();
// Never returns: serves the setup page until credentials are saved, then reboots.
// A configured device that merely failed to join reboots and retries every 3 min.
[[noreturn]] void runSetupPortal(WebServer& server, const char* apPrefix, const char* hostname);

// HTML text/attribute escaping (inputs such as scanned SSIDs are attacker-controlled).
String htmlEscape(const String& s);

}  // namespace web
