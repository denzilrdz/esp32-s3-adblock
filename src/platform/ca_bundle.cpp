#include "platform/ca_bundle.h"

#include <esp_crt_bundle.h>
#include <sdkconfig.h>

#include "platform/psram.h"
#include "util/ca_bundle.h"

// The bundle compiled into the prebuilt ESP-IDF libraries (esp_crt_bundle.c).
extern const uint8_t kBuiltinBundleStart[] asm("_binary_x509_crt_bundle_start");
extern const uint8_t kBuiltinBundleEnd[] asm("_binary_x509_crt_bundle_end");

namespace platform {

namespace {
constexpr const char* kTag = "tls";
}

bool installTrustedCaBundle(hal::ILogger& log) {
  const size_t len = static_cast<size_t>(kBuiltinBundleEnd - kBuiltinBundleStart);
  // esp_crt_bundle_set() keeps a pointer, not a copy: the buffer lives for the whole
  // uptime (PSRAM; mbedTLS only reads it from task context during verification).
  uint8_t* copy = static_cast<uint8_t*>(allocLarge(len));
  if (!copy) {
    log.log(hal::LogLevel::kError, kTag, "no memory to filter the CA bundle: using the built-in one");
    return false;
  }
  size_t removed = 0;
  const size_t n = util::filterCaBundle(kBuiltinBundleStart, len, util::kDistrustedRoots,
                                        util::kDistrustedRootCount, copy, len, &removed);
  if (n == 0 || !util::caBundleValid(copy, n, CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS) ||
      esp_crt_bundle_set(copy, n) != ESP_OK) {
    log.log(hal::LogLevel::kError, kTag, "CA bundle format not understood: using the built-in one (%u bytes)",
            static_cast<unsigned>(len));
    return false;
  }
  log.log(hal::LogLevel::kInfo, kTag, "CA bundle: %u roots, %u distrusted removed",
          static_cast<unsigned>(util::caBundleCount(copy, n)), static_cast<unsigned>(removed));
  return true;
}

}  // namespace platform
