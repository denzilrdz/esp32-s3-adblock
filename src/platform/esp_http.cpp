#include "platform/esp_http.h"

#include <esp_http_client.h>
#include <esp_task_wdt.h>
#include <strings.h>

#include <cstdio>
#include <cstring>

#include "platform/crt_bundle.h"

namespace platform {

namespace {

constexpr int kMaxRedirects = 5;

struct Context {
  char etag[96];
};

esp_err_t onEvent(esp_http_client_event_t* evt) {
  if (evt->event_id == HTTP_EVENT_ON_HEADER && evt->header_key && evt->header_value &&
      strcasecmp(evt->header_key, "ETag") == 0) {
    auto* ctx = static_cast<Context*>(evt->user_data);
    snprintf(ctx->etag, sizeof(ctx->etag), "%s", evt->header_value);
  }
  return ESP_OK;
}

bool isRedirect(int status) {
  return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

}  // namespace

hal::HttpGetResult EspHttpClient::get(const hal::HttpGetRequest& req, hal::IHttpBodySink& sink) {
  hal::HttpGetResult result;
  if (!req.url || strncmp(req.url, "https://", 8) != 0) {  // HTTPS only, by design
    result.error = hal::HttpError::kConnect;
    return result;
  }
  Context ctx = {};

  esp_http_client_config_t cfg = {};
  cfg.url = req.url;
  cfg.method = HTTP_METHOD_GET;
  cfg.timeout_ms = static_cast<int>(req.timeoutMs);
  cfg.crt_bundle_attach = esp_crt_bundle_attach;  // verify server certificates
  cfg.disable_auto_redirect = true;               // handled below, so we see each status
  cfg.event_handler = onEvent;
  cfg.user_data = &ctx;
  cfg.buffer_size = 2048;
  esp_http_client_handle_t client = esp_http_client_init(&cfg);
  if (!client) {
    result.error = hal::HttpError::kConnect;
    return result;
  }
  if (req.ifNoneMatch && req.ifNoneMatch[0]) esp_http_client_set_header(client, "If-None-Match", req.ifNoneMatch);

  int status = 0;
  for (int hop = 0; hop <= kMaxRedirects; hop++) {
    ctx.etag[0] = 0;
    if (esp_http_client_open(client, 0) != ESP_OK) {
      result.error = hal::HttpError::kConnect;
      esp_http_client_cleanup(client);
      return result;
    }
    result.contentLength = esp_http_client_fetch_headers(client);
    status = esp_http_client_get_status_code(client);
    esp_task_wdt_reset();
    if (!isRedirect(status)) break;
    int discarded = 0;
    esp_http_client_flush_response(client, &discarded);
    if (esp_http_client_set_redirection(client) != ESP_OK) break;
    // Never follow a redirect to plain http: the list's CRC only detects
    // corruption, so authenticity depends on TLS for every hop.
    char next[512] = {0};
    if (esp_http_client_get_url(client, next, sizeof(next)) != ESP_OK || strncmp(next, "https://", 8) != 0) {
      result.error = hal::HttpError::kConnect;
      esp_http_client_close(client);
      esp_http_client_cleanup(client);
      return result;
    }
  }
  result.status = status;
  snprintf(result.etag, sizeof(result.etag), "%s", ctx.etag);

  if (status == 200) {
    uint8_t buf[1024];
    while (true) {
      const int n = esp_http_client_read(client, reinterpret_cast<char*>(buf), sizeof(buf));
      esp_task_wdt_reset();  // long downloads must not trip the watchdog
      if (n < 0) {
        result.error = hal::HttpError::kTimeout;
        break;
      }
      if (n == 0) break;
      if (!sink.onBodyChunk(buf, static_cast<size_t>(n))) {
        result.error = hal::HttpError::kAborted;
        break;
      }
      result.bodyBytes += static_cast<size_t>(n);
    }
    if (result.error == hal::HttpError::kNone && !esp_http_client_is_complete_data_received(client))
      result.error = hal::HttpError::kTruncated;
  }
  esp_http_client_close(client);
  esp_http_client_cleanup(client);
  return result;
}

}  // namespace platform
