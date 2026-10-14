#include "platform/transports.h"

#include <esp_timer.h>
#include <lwip/sockets.h>

#include <cstring>

namespace platform {

using upstream::IoStatus;

namespace {

constexpr uint32_t kWriteTimeoutMs = 2000;

uint64_t nowMs() {
  return static_cast<uint64_t>(esp_timer_get_time() / 1000);
}

IoStatus fromStream(StreamStatus s) {
  switch (s) {
    case StreamStatus::kOk: return IoStatus::kOk;
    case StreamStatus::kTimeout: return IoStatus::kTimeout;
    case StreamStatus::kClosed: return IoStatus::kClosed;
    case StreamStatus::kError: return IoStatus::kError;
  }
  return IoStatus::kError;
}

}  // namespace

// --- DoT ------------------------------------------------------------------------

DotTransport::DotTransport(const char* name, const char* ipv4, const char* verifyName, uint16_t port)
    : name_(name), tls_(ipv4, port, verifyName), deframer_(rxStore_, sizeof(rxStore_)) {}

IoStatus DotTransport::connect(uint32_t timeoutMs) {
  deframer_.reset();
  return tls_.connect(timeoutMs) ? IoStatus::kOk : IoStatus::kError;
}

IoStatus DotTransport::send(const uint8_t* msg, size_t len) {
  const size_t n = upstream::frameForStream(msg, len, txBuf_, sizeof(txBuf_));
  if (n == 0) return IoStatus::kError;
  return fromStream(tls_.writeAll(txBuf_, n, kWriteTimeoutMs));
}

IoStatus DotTransport::receive(uint8_t* buf, size_t cap, size_t& len, uint32_t timeoutMs) {
  const uint64_t deadline = nowMs() + timeoutMs;
  while (true) {
    len = deframer_.next(buf, cap);
    if (len) return IoStatus::kOk;
    if (deframer_.failed()) return IoStatus::kError;
    const uint64_t now = nowMs();
    const uint32_t remaining = now >= deadline ? 0 : static_cast<uint32_t>(deadline - now);
    uint8_t chunk[512];
    size_t got = 0;
    const StreamStatus st = tls_.read(chunk, sizeof(chunk), got, remaining);
    if (st != StreamStatus::kOk) return fromStream(st);
    if (!deframer_.feed(chunk, got)) return IoStatus::kError;
  }
}

void DotTransport::close() {
  tls_.close();
  deframer_.reset();
}

// --- DoH ------------------------------------------------------------------------

DohTransport::DohTransport(const char* name, const char* ipv4, const char* host, const char* path,
                           uint16_t port)
    : name_(name), host_(host), path_(path), tls_(ipv4, port, host), parser_(rxStore_, sizeof(rxStore_)) {}

IoStatus DohTransport::connect(uint32_t timeoutMs) {
  parser_.reset();
  return tls_.connect(timeoutMs) ? IoStatus::kOk : IoStatus::kError;
}

IoStatus DohTransport::send(const uint8_t* msg, size_t len) {
  const size_t head = upstream::buildDohRequestHead(host_, path_, len, txBuf_, sizeof(txBuf_));
  if (head == 0 || head + len > sizeof(txBuf_)) return IoStatus::kError;
  memcpy(txBuf_ + head, msg, len);
  parser_.reset();
  return fromStream(tls_.writeAll(txBuf_, head + len, kWriteTimeoutMs));
}

IoStatus DohTransport::receive(uint8_t* buf, size_t cap, size_t& len, uint32_t timeoutMs) {
  using State = upstream::HttpResponseParser::State;
  const uint64_t deadline = nowMs() + timeoutMs;
  while (parser_.state() == State::kHead || parser_.state() == State::kBody) {
    const uint64_t now = nowMs();
    const uint32_t remaining = now >= deadline ? 0 : static_cast<uint32_t>(deadline - now);
    uint8_t chunk[512];
    size_t got = 0;
    const StreamStatus st = tls_.read(chunk, sizeof(chunk), got, remaining);
    if (st != StreamStatus::kOk) return fromStream(st);
    parser_.feed(chunk, got);
  }
  if (parser_.state() != State::kComplete || parser_.status() != 200 || !parser_.dnsMessageType() ||
      parser_.bodyLen() > cap) {
    close();  // a broken HTTP exchange leaves the stream in an unknown state
    return IoStatus::kError;
  }
  memcpy(buf, parser_.body(), parser_.bodyLen());
  len = parser_.bodyLen();
  const bool keep = parser_.keepAlive();
  parser_.reset();
  if (!keep) tls_.close();
  return IoStatus::kOk;
}

void DohTransport::close() {
  tls_.close();
  parser_.reset();
}

// --- Plain UDP ----------------------------------------------------------------------

UdpTransport::UdpTransport(const char* name, const char* ipv4, uint16_t port) : name_(name), port_(port) {
  strncpy(ip_, ipv4, sizeof(ip_) - 1);
  ip_[sizeof(ip_) - 1] = 0;
}

IoStatus UdpTransport::connect(uint32_t) {
  close();
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port_);
  if (inet_pton(AF_INET, ip_, &addr.sin_addr) != 1) return IoStatus::kError;
  fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd_ < 0) return IoStatus::kError;
  // connect() on UDP fixes the peer: datagrams from any other source are dropped
  // by the stack. A fresh socket (new source port) is used after every idle close.
  if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
    close();
    return IoStatus::kError;
  }
  return IoStatus::kOk;
}

IoStatus UdpTransport::send(const uint8_t* msg, size_t len) {
  if (fd_ < 0) return IoStatus::kError;
  return ::send(fd_, msg, len, 0) == static_cast<int>(len) ? IoStatus::kOk : IoStatus::kError;
}

IoStatus UdpTransport::receive(uint8_t* buf, size_t cap, size_t& len, uint32_t timeoutMs) {
  if (fd_ < 0) return IoStatus::kError;
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(fd_, &rfds);
  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  const int r = select(fd_ + 1, &rfds, nullptr, nullptr, &tv);
  if (r == 0) return IoStatus::kTimeout;
  if (r < 0) return IoStatus::kError;
  const int n = ::recv(fd_, buf, cap, MSG_DONTWAIT);
  if (n <= 0) return IoStatus::kTimeout;
  len = static_cast<size_t>(n);
  return IoStatus::kOk;
}

void UdpTransport::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

}  // namespace platform
