#pragma once
// Installs the TLS certificate bundle without distrusted roots (util::kDistrustedRoots).
// Call once at boot, before any TLS connection: DoT/DoH (TlsStream) and the blocklist
// download (esp_http_client) both verify against the installed bundle.

#include <esp_err.h>

#include "hal/logger.h"

namespace platform {

// True if a filtered bundle is installed. On failure (e.g. a future ESP-IDF changes the
// bundle format) it logs an error and leaves the built-in bundle in place, so encrypted
// DNS keeps working.
bool installTrustedCaBundle(hal::ILogger& log);

// Use instead of esp_crt_bundle_attach() everywhere (TlsStream, esp_http_client's
// crt_bundle_attach). ESP-IDF keeps the bundle in one global: esp_crt_bundle_detach()
// (esp-tls calls it whenever an esp_http_client connection closes) clears it, and the
// next esp_crt_bundle_attach() then reloads the BUILT-IN bundle, distrusted roots and
// all. This sets the filtered bundle before and after attaching, so the global only
// ever holds the filtered bundle or nothing (and nothing fails verification: closed).
// The upstream transports attach once at boot (TlsStream::prepare()), so after boot
// only the blocklist download (loopTask) attaches and detaches: no other task can
// slip a detach between this function's set and attach.
esp_err_t attachTrustedBundle(void* conf);

// Puts the filtered bundle back after something detached it (an esp_http_client
// download), so the global isn't left empty.
void reinstallTrustedBundle();

}  // namespace platform
