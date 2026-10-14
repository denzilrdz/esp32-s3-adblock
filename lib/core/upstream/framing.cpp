#include "upstream/framing.h"

#include <cstdio>
#include <cstring>

#include "util/bytes.h"

namespace upstream {

namespace {

constexpr size_t kMaxContentLength = 65535;  // a DNS message never exceeds this

char lower(char c) {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}

// Case-insensitive compare of [p, p+n) with a lowercase literal.
bool equalsCi(const char* p, size_t n, const char* lit) {
  const size_t m = strlen(lit);
  if (n != m) return false;
  for (size_t i = 0; i < n; i++)
    if (lower(p[i]) != lit[i]) return false;
  return true;
}

// Trims spaces/tabs from both ends of [p, p+n).
void trim(const char*& p, size_t& n) {
  while (n && (*p == ' ' || *p == '\t')) {
    p++;
    n--;
  }
  while (n && (p[n - 1] == ' ' || p[n - 1] == '\t')) n--;
}

bool containsTokenCi(const char* p, size_t n, const char* token) {
  const size_t m = strlen(token);
  for (size_t i = 0; i + m <= n; i++) {
    bool hit = true;
    for (size_t k = 0; k < m && hit; k++) hit = lower(p[i + k]) == token[k];
    if (hit) return true;
  }
  return false;
}

}  // namespace

size_t frameForStream(const uint8_t* msg, size_t len, uint8_t* out, size_t cap) {
  if (len > 0xFFFF || len + 2 > cap) return 0;
  util::writeU16Be(out, static_cast<uint16_t>(len));
  memcpy(out + 2, msg, len);
  return len + 2;
}

bool StreamDeframer::feed(const uint8_t* data, size_t len) {
  if (failed_) return false;
  if (len > cap_ - len_) {
    failed_ = true;
    return false;
  }
  memcpy(buf_ + len_, data, len);
  len_ += len;
  if (len_ >= 2 && static_cast<size_t>(util::readU16Be(buf_)) + 2 > cap_) {
    failed_ = true;  // this frame can never fit
    return false;
  }
  return true;
}

size_t StreamDeframer::next(uint8_t* out, size_t cap) {
  if (failed_ || len_ < 2) return 0;
  const size_t msgLen = util::readU16Be(buf_);
  if (len_ < msgLen + 2) return 0;
  if (msgLen > cap) {
    failed_ = true;
    return 0;
  }
  memcpy(out, buf_ + 2, msgLen);
  memmove(buf_, buf_ + 2 + msgLen, len_ - 2 - msgLen);
  len_ -= 2 + msgLen;
  return msgLen;
}

size_t buildDohRequestHead(const char* host, const char* path, size_t bodyLen, uint8_t* out, size_t cap) {
  const int n = snprintf(reinterpret_cast<char*>(out), cap,
                         "POST %s HTTP/1.1\r\n"
                         "Host: %s\r\n"
                         "Content-Type: application/dns-message\r\n"
                         "Accept: application/dns-message\r\n"
                         "Content-Length: %u\r\n"
                         "Connection: keep-alive\r\n"
                         "\r\n",
                         path, host, static_cast<unsigned>(bodyLen));
  if (n <= 0 || static_cast<size_t>(n) >= cap) return 0;
  return static_cast<size_t>(n);
}

void HttpResponseParser::reset() {
  len_ = 0;
  state_ = State::kHead;
  status_ = 0;
  keepAlive_ = true;
  dnsType_ = false;
  bodyStart_ = 0;
  contentLength_ = 0;
}

bool HttpResponseParser::parseHead(size_t headEnd) {
  const char* s = reinterpret_cast<const char*>(buf_);
  // Status line: HTTP/1.x SP 3DIGIT SP reason
  const char* eol = static_cast<const char*>(memchr(s, '\r', headEnd));
  if (!eol || eol - s < 12 || memcmp(s, "HTTP/1.", 7) != 0 || s[8] != ' ') return false;
  if (s[7] == '0') keepAlive_ = false;  // HTTP/1.0 defaults to close
  for (int i = 9; i < 12; i++)
    if (s[i] < '0' || s[i] > '9') return false;
  status_ = (s[9] - '0') * 100 + (s[10] - '0') * 10 + (s[11] - '0');

  bool haveLength = false;
  const char* line = eol + 2;
  const char* end = s + headEnd;
  while (line < end) {
    const char* le = static_cast<const char*>(memchr(line, '\r', static_cast<size_t>(end - line)));
    if (!le) le = end;
    const char* colon = static_cast<const char*>(memchr(line, ':', static_cast<size_t>(le - line)));
    if (!colon) return false;
    const char* name = line;
    size_t nameLen = static_cast<size_t>(colon - line);
    const char* value = colon + 1;
    size_t valueLen = static_cast<size_t>(le - value);
    trim(name, nameLen);
    trim(value, valueLen);
    if (equalsCi(name, nameLen, "content-length")) {
      if (valueLen == 0 || valueLen > 6 || haveLength) return false;
      size_t v = 0;
      for (size_t i = 0; i < valueLen; i++) {
        if (value[i] < '0' || value[i] > '9') return false;
        v = v * 10 + static_cast<size_t>(value[i] - '0');
      }
      if (v > kMaxContentLength) return false;
      contentLength_ = v;
      haveLength = true;
    } else if (equalsCi(name, nameLen, "transfer-encoding")) {
      return false;  // chunked bodies are not supported
    } else if (equalsCi(name, nameLen, "connection")) {
      if (containsTokenCi(value, valueLen, "close")) keepAlive_ = false;
      if (containsTokenCi(value, valueLen, "keep-alive")) keepAlive_ = true;
    } else if (equalsCi(name, nameLen, "content-type")) {
      dnsType_ = valueLen >= 23 && equalsCi(value, 23, "application/dns-message");
    }
    line = le + 2;
  }
  if (!haveLength) return false;  // we cannot frame the body otherwise
  return true;
}

HttpResponseParser::State HttpResponseParser::feed(const uint8_t* data, size_t len) {
  if (state_ == State::kError || state_ == State::kComplete) {
    if (len) state_ = State::kError;  // unexpected extra bytes
    return state_;
  }
  if (len > cap_ - len_) return state_ = State::kError;
  memcpy(buf_ + len_, data, len);
  len_ += len;

  if (state_ == State::kHead) {
    // Look for the blank line that ends the head.
    size_t headEnd = 0;
    for (size_t i = 3; i < len_; i++) {
      if (buf_[i - 3] == '\r' && buf_[i - 2] == '\n' && buf_[i - 1] == '\r' && buf_[i] == '\n') {
        headEnd = i - 1;  // points at the second "\r\n"
        break;
      }
    }
    if (!headEnd) return state_;
    if (!parseHead(headEnd)) return state_ = State::kError;
    bodyStart_ = headEnd + 2;
    if (bodyStart_ + contentLength_ > cap_) return state_ = State::kError;
    state_ = State::kBody;
  }
  if (len_ > bodyStart_ + contentLength_) return state_ = State::kError;  // pipelined junk
  if (len_ == bodyStart_ + contentLength_) state_ = State::kComplete;
  return state_;
}

}  // namespace upstream
