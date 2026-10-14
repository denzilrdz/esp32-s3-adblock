#pragma once
// Scripted IHttpClient: returns one canned response per call and records requests.

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "hal/http_client.h"

class FakeHttpClient final : public hal::IHttpClient {
 public:
  struct Response {
    hal::HttpError error = hal::HttpError::kNone;
    int status = 200;
    std::vector<uint8_t> body;
    std::string etag;
    size_t chunk = 1000;       // delivery chunk size
    bool truncateHalf = false; // deliver half the body, then report kTruncated
  };

  hal::HttpGetResult get(const hal::HttpGetRequest& req, hal::IHttpBodySink& sink) override {
    requests.push_back({req.url ? req.url : "", req.ifNoneMatch ? req.ifNoneMatch : ""});
    hal::HttpGetResult r;
    r.error = next.error;
    r.status = next.status;
    snprintf(r.etag, sizeof(r.etag), "%s", next.etag.c_str());
    if (next.error == hal::HttpError::kConnect || next.error == hal::HttpError::kTimeout) {
      r.status = 0;
      return r;
    }
    if (next.status != 200) return r;
    r.contentLength = static_cast<int64_t>(next.body.size());
    const size_t limit = next.truncateHalf ? next.body.size() / 2 : next.body.size();
    for (size_t i = 0; i < limit; i += next.chunk) {
      const size_t n = std::min(next.chunk, limit - i);
      if (!sink.onBodyChunk(next.body.data() + i, n)) {
        r.error = hal::HttpError::kAborted;
        return r;
      }
      r.bodyBytes += n;
    }
    if (next.truncateHalf) r.error = hal::HttpError::kTruncated;
    return r;
  }

  struct Request {
    std::string url;
    std::string ifNoneMatch;
  };
  Response next;
  std::vector<Request> requests;
};
