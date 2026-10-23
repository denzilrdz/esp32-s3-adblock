#pragma once
// IHttpClient over ESP-IDF's esp_http_client: HTTPS with CA-bundle verification,
// redirects (GitHub release -> CDN), If-None-Match/ETag, streamed body.

#include "diag/liveness.h"
#include "hal/http_client.h"

namespace platform {

class EspHttpClient final : public hal::IHttpClient {
 public:
  // get() pauses the hardware task watchdog (see esp_http.cpp); this software one
  // (armed for the whole call, limit set by the caller) restarts the board if the
  // download hangs anyway.
  void setLiveness(diag::LivenessMonitor* monitor, int id) {
    liveness_ = monitor;
    livenessId_ = id;
  }
  hal::HttpGetResult get(const hal::HttpGetRequest& req, hal::IHttpBodySink& sink) override;

 private:
  diag::LivenessMonitor* liveness_ = nullptr;
  int livenessId_ = -1;
};

}  // namespace platform
