#pragma once
// A WebServer route that refuses oversized request bodies before they are read.
//
// Arduino's WebServer reads a non-multipart POST body into one realloc-grown heap
// buffer sized only by the client's Content-Length, before any handler runs and for
// unknown URLs too; "Content-Length: -1" turns into SIZE_MAX. Any LAN host, without
// logging in, could fill PSRAM with it and break the 02:00 blocklist swap (audit
// 2026-11). The library calls canRaw() once the headers are in and before reading the
// body, so a too-large (or negative) Content-Length is answered with 413 there and
// the connection closed: the body is never buffered.
//
// Multipart uploads (blocklist, firmware, settings file) don't take this path: their
// file parts are streamed to the route's upload function piece by piece.
//
// Register every route with this (uri nullptr = any URL: the not-found handler, last).

#include <WebServer.h>

#include <functional>

namespace web {

class BoundedRoute : public RequestHandler {
 public:
  static constexpr int kMaxBody = 8192;  // the dashboard's largest form post is ~1 KB

  BoundedRoute(const char* uri, HTTPMethod method, std::function<void()> fn,
               std::function<void()> upload = nullptr, int maxBody = kMaxBody)
      : uri_(uri), method_(method), fn_(std::move(fn)), upload_(std::move(upload)), maxBody_(maxBody) {}

  bool canHandle(WebServer&, HTTPMethod method, const String& uri) override {
    return (method_ == HTTP_ANY || method == method_) && (!uri_ || uri == uri_);
  }
  bool canUpload(WebServer& server, const String& uri) override {
    return upload_ && canHandle(server, HTTP_POST, uri);
  }
  bool canRaw(WebServer& server, const String&) override {
    const int len = server.clientContentLength();
    return len < 0 || len > maxBody_;
  }
  void raw(WebServer& server, const String&, HTTPRaw& raw) override {
    if (raw.status != RAW_START) return;
    NetworkClient& c = server.client();
    c.print("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    c.stop();  // the library's next read returns 0: RAW_ABORTED, the request ends
  }
  bool handle(WebServer&, HTTPMethod, const String&) override {
    fn_();
    return true;
  }
  void upload(WebServer&, const String&, HTTPUpload&) override {
    if (upload_) upload_();
  }

 private:
  const char* uri_;
  HTTPMethod method_;
  std::function<void()> fn_;
  std::function<void()> upload_;
  int maxBody_;
};

}  // namespace web
