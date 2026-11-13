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

// Reassembles length-prefixed messages from an arbitrary byte stream. A frame too big
// for the buffer (a DoT server may ignore our EDNS size and send a huge answer) is
// skipped and counted, not treated as a broken connection: that would tear down every
// other query on it, and the same answer would then fail each upstream in turn.
class StreamDeframer {
 public:
  StreamDeframer(uint8_t* buf, size_t cap) : buf_(buf), cap_(cap) {}

  // Appends received bytes. False only if complete messages that were not taken with
  // next() leave no room (caller must close the connection).
  bool feed(const uint8_t* data, size_t len);
  // Copies the next complete message into out and returns its length; 0 if none yet
  // (or if `cap` is too small, which is treated as an error by returning 0 and
  // setting failed()).
  size_t next(uint8_t* out, size_t cap);
  bool failed() const { return failed_; }
  size_t buffered() const { return len_; }
  uint32_t skipped() const { return skipped_; }  // oversized frames dropped so far
  // The DNS ID of an oversized frame dropped since the last call, oldest first.
  bool takeDropped(uint16_t& id);
  void reset() {
    len_ = 0;
    skip_ = 0;
    failed_ = false;
    droppedCount_ = 0;
  }

 private:
  void dropOversizedHead();

  uint8_t* buf_;
  size_t cap_;
  size_t len_ = 0;
  size_t skip_ = 0;  // bytes of an oversized frame still to discard
  uint32_t skipped_ = 0;
  bool failed_ = false;
  uint16_t droppedIds_[4] = {};  // IDs of dropped frames not yet taken (newest lost if full)
  uint8_t droppedCount_ = 0;
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
  // kComplete, but the body was larger than the buffer and was skipped: bodyLen() is
  // 0 and tooBigId() holds the answer's DNS ID if it had at least 2 bytes.
  bool tooBig() const { return tooBig_; }
  bool tooBigId(uint16_t& id) const {
    id = tooBigId_;
    return tooBigSeen_ >= 2;
  }
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
  bool tooBig_ = false;
  size_t skipLeft_ = 0;  // body bytes still to discard while tooBig_
  uint16_t tooBigId_ = 0;
  uint8_t tooBigSeen_ = 0;
  void skipBody(const uint8_t* data, size_t len);
};

}  // namespace upstream
