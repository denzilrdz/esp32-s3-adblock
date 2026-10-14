#pragma once
// IHttpClient over ESP-IDF's esp_http_client: HTTPS with CA-bundle verification,
// redirects (GitHub release -> CDN), If-None-Match/ETag, streamed body.

#include "hal/http_client.h"

namespace platform {

class EspHttpClient final : public hal::IHttpClient {
 public:
  hal::HttpGetResult get(const hal::HttpGetRequest& req, hal::IHttpBodySink& sink) override;
};

}  // namespace platform
