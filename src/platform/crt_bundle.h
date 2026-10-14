#pragma once
// ESP-IDF's CA bundle hook (components/mbedtls/esp_crt_bundle). Declared here because
// <esp_crt_bundle.h> resolves to the Arduino WiFiClientSecure copy of that header,
// which declares differently named arduino_* functions instead. Signature confirmed
// in tools/sdk/<chip>/include/mbedtls/esp_crt_bundle/include/esp_crt_bundle.h.

#include <esp_err.h>

extern "C" esp_err_t esp_crt_bundle_attach(void* conf);
