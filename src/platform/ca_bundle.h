#pragma once
// Installs the TLS certificate bundle without distrusted roots (util::kDistrustedRoots).
// Call once at boot, before any TLS connection: DoT/DoH (TlsStream) and the blocklist
// download (esp_http_client) both verify against the installed bundle.

#include "hal/logger.h"

namespace platform {

// True if a filtered bundle is installed. On failure (e.g. a future ESP-IDF changes the
// bundle format) it logs an error and leaves the built-in bundle in place, so encrypted
// DNS keeps working.
bool installTrustedCaBundle(hal::ILogger& log);

}  // namespace platform
