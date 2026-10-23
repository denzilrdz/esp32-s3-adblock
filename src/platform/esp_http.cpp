#include "platform/esp_http.h"

#include "platform/watchdog.h"

#include <esp_http_client.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>
#include <strings.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

#include <esp_crt_bundle.h>

namespace platform {

namespace {

constexpr int kMaxRedirects = 5;
// GitHub release downloads redirect to release-assets.githubusercontent.com with a
// signed query string of ~900 characters; leave room for longer tokens.
constexpr int kMaxUrlLen = 2048;

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

// Upper bound for one whole download (all hops, the body included). The watchdog is
// paused meanwhile (see get()), so this is what stops a stalled transfer.
constexpr int64_t kMaxDownloadUs = 5LL * 60 * 1000 * 1000;

bool isRedirect(int status) {
  return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

}  // namespace

hal::HttpGetResult EspHttpClient::get(const hal::HttpGetRequest& req, hal::IHttpBodySink& sink) {
  // Every step below has a timeout (req.timeoutMs, up to 20 s per read), but the DNS
  // lookup + TCP connect + TLS handshake inside esp_http_client_open(), per hop, give
  // no chance to feed the 5 s task watchdog: one slow moment at the 03:00 update then
  // restarted the board. So the watchdog is paused and kMaxDownloadUs bounds the whole.
  WatchdogPause noWatchdog;
  const int64_t startUs = esp_timer_get_time();
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
  cfg.buffer_size_tx = kMaxUrlLen;  // the request line carries the full redirect URL
  esp_http_client_handle_t client = esp_http_client_init(&cfg);
  if (!client) {
    result.error = hal::HttpError::kConnect;
    return result;
  }
  if (req.ifNoneMatch && req.ifNoneMatch[0])
    esp_http_client_set_header(client, "If-None-Match", req.ifNoneMatch);

  // Heap, not stack: this runs in the maintenance task next to a TLS handshake.
  std::unique_ptr<char, void (*)(void*)> next(static_cast<char*>(malloc(kMaxUrlLen)), free);
  if (!next) {
    result.error = hal::HttpError::kConnect;
    esp_http_client_cleanup(client);
    return result;
  }
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
    if (!isRedirect(status)) break;
    int discarded = 0;
    esp_http_client_flush_response(client, &discarded);
    if (esp_http_client_set_redirection(client) != ESP_OK) break;
    // Never follow a redirect to plain http: the list's CRC only detects
    // corruption, so authenticity depends on TLS for every hop.
    next.get()[0] = 0;
    if (esp_http_client_get_url(client, next.get(), kMaxUrlLen) != ESP_OK ||
        strncmp(next.get(), "https://", 8) != 0) {
      result.error = hal::HttpError::kRedirect;
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
      if (n < 0 || esp_timer_get_time() - startUs > kMaxDownloadUs) {
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
