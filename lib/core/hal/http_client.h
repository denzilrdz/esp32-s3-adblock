#pragma once
// Streaming HTTPS GET used by the blocklist updater. The implementation must verify
// server certificates (CA bundle); there is no "insecure" option on purpose.

#include <cstddef>
#include <cstdint>

namespace hal {

// Receives the body in chunks. Return false to abort the transfer.
class IHttpBodySink {
 public:
  virtual ~IHttpBodySink() = default;
  virtual bool onBodyChunk(const uint8_t* data, size_t len) = 0;
};

struct HttpGetRequest {
  const char* url = nullptr;
  const char* ifNoneMatch = nullptr;  // previous ETag, or null
  uint32_t timeoutMs = 20000;         // per read, not total
};

enum class HttpError {
  kNone,        // a response was received (check status)
  kConnect,     // DNS/TCP/TLS failure
  kTimeout,
  kAborted,     // sink returned false
  kTruncated,   // connection closed before Content-Length bytes
};

struct HttpGetResult {
  HttpError error = HttpError::kNone;
  int status = 0;              // 200, 304, 404 ...
  int64_t contentLength = -1;  // -1 if unknown
  size_t bodyBytes = 0;        // bytes delivered to the sink
  char etag[96] = {0};         // ETag response header, if any
};

class IHttpClient {
 public:
  virtual ~IHttpClient() = default;
  // Follows redirects. The body is passed to `sink` only for a final 200 response;
  // other statuses (304, 404, ...) are reported in the result without a body.
  virtual HttpGetResult get(const HttpGetRequest& req, IHttpBodySink& sink) = 0;
};

}  // namespace hal
