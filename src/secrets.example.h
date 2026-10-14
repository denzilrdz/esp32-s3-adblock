#pragma once
// Copy this file to src/secrets.h (gitignored) and edit it. These are FIRST-BOOT
// DEFAULTS only: settings changed on the dashboard are stored in NVS and win.

// Optional: Wi-Fi to join. Leave the placeholders to use the setup access point
// ("S3-AdBlock-XXXX") and its captive portal instead.
static const char* const WIFI_SSID = "YOUR_WIFI_SSID";
static const char* const WIFI_PASS = "YOUR_WIFI_PASSWORD";

// Dashboard login. If WEB_PASS is left as the placeholder (or shorter than 10
// characters) it never works: the device prints a one-time setup code on the serial
// console, and you set the real password on the dashboard with it. The password is
// then stored as a PBKDF2 hash in NVS.
static const char* const WEB_USER = "admin";
static const char* const WEB_PASS = "CHANGE_ME_WEB_PASSWORD";

// Network firmware updates (pio run -t upload --upload-protocol espota). ArduinoOTA
// stays disabled until this is a real password of 10+ characters.
static const char* const OTA_PASS = "CHANGE_ME_OTA_PASSWORD";
