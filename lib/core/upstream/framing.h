#pragma once
// Wire framing for stream transports:
//  - DNS over TCP/TLS (RFC 7766 / 7858): each message is prefixed by a 2-byte length.
//  - DNS over HTTPS (RFC 8484) over HTTP/1.1: POST application/dns-message with a
//    Content-Length body. Chunked responses are not supported (Cloudflare sends
//    Content-Length); they are reported as an error so the chain moves on.
// Both parsers work on caller-provided buffers and never allocate.

#include <cstddef>
#include <cstdint>

namespace upstream {

// Writes the 2-byte length prefix + message. Returns total size, or 0 if it won't fit.
size_t frameForStream(const uint8_t* msg, size_t len, uint8_t* out, size_t cap);

// Reassembles length-prefixed messages from an arbitrary byte stream.
class StreamDeframer {
 public:
  StreamDeframer(uint8_t* buf, size_t cap) : buf_(buf), cap_(cap) {}

  // Appends received bytes. False if a frame can never fit the buffer (caller must
  // close the connection) or the input does not fit right now.
  bool feed(const uint8_t* data, size_t len);
  // Copies the next complete message into out and returns its length; 0 if none yet
  // (or if `cap` is too small, which is treated as an error by returning 0 and
  // setting failed()).
  size_t next(uint8_t* out, size_t cap);
  bool failed() const { return failed_; }
  size_t buffered() const { return len_; }
  void reset() {
    len_ = 0;
    failed_ = false;
  }

 private:
  uint8_t* buf_;
  size_t cap_;
  size_t len_ = 0;
  bool failed_ = false;
};

// Builds the HTTP/1.1 request head for a DoH POST. The DNS message follows as the body.
size_t buildDohRequestHead(const char* host, const char* path, size_t bodyLen, uint8_t* out, size_t cap);

// Incremental HTTP/1.1 response parser for DoH replies.
class HttpResponseParser {
 public:
  enum class State { kHead, kBody, kComplete, kError };

  HttpResponseParser(uint8_t* buf, size_t cap) : buf_(buf), cap_(cap) {}

  // Feeds received bytes; returns the new state. Bytes past the end of this response
  // are rejected (no HTTP pipelining) and put the parser in kError.
  State feed(const uint8_t* data, size_t len);

  State state() const { return state_; }
  int status() const { return status_; }
  bool keepAlive() const { return keepAlive_; }
  bool dnsMessageType() const { return dnsType_; }
  const uint8_t* body() const { return buf_ + bodyStart_; }
  size_t bodyLen() const { return contentLength_; }
  void reset();

 private:
  bool parseHead(size_t headEnd);

  uint8_t* buf_;
  size_t cap_;
  size_t len_ = 0;
  State state_ = State::kHead;
  int status_ = 0;
  bool keepAlive_ = true;
  bool dnsType_ = false;
  size_t bodyStart_ = 0;
  size_t contentLength_ = 0;
};

}  // namespace upstream
