#pragma once
// ESP32 implementations of upstream::ITransport: DNS-over-TLS, DNS-over-HTTPS
// (HTTP/1.1 POST) and plain UDP. Each owns its socket/TLS session (RAII).

#include <cstddef>
#include <cstdint>

#include "platform/tls_stream.h"
#include "upstream/forwarder.h"
#include "upstream/framing.h"
#include "upstream/transport.h"

namespace platform {

// RFC 7858: 2-byte length-prefixed DNS messages over TLS on port 853. Pipelined.
class DotTransport final : public upstream::ITransport {
 public:
  DotTransport(const char* name, const char* ipv4, const char* verifyName, uint16_t port = 853);

  const char* name() const override { return name_; }
  upstream::TransportKind kind() const override { return upstream::TransportKind::kDoT; }
  bool authenticated() const override { return true; }
  bool pipelined() const override { return true; }
  bool connected() const override { return tls_.connected(); }
  upstream::IoStatus connect(uint32_t timeoutMs) override;
  upstream::IoStatus send(const uint8_t* msg, size_t len) override;
  upstream::IoStatus receive(uint8_t* buf, size_t cap, size_t& len, uint32_t timeoutMs) override;
  void close() override;

 private:
  const char* name_;
  TlsStream tls_;
  uint8_t rxStore_[upstream::Forwarder::kMaxAnswer + 2];
  upstream::StreamDeframer deframer_;
  uint8_t txBuf_[514];
};

// RFC 8484 over HTTP/1.1 keep-alive. One request at a time (no HTTP pipelining).
class DohTransport final : public upstream::ITransport {
 public:
  DohTransport(const char* name, const char* ipv4, const char* host, const char* path = "/dns-query",
               uint16_t port = 443);

  const char* name() const override { return name_; }
  upstream::TransportKind kind() const override { return upstream::TransportKind::kDoH; }
  bool authenticated() const override { return true; }
  bool pipelined() const override { return false; }
  bool connected() const override { return tls_.connected(); }
  upstream::IoStatus connect(uint32_t timeoutMs) override;
  upstream::IoStatus send(const uint8_t* msg, size_t len) override;
  upstream::IoStatus receive(uint8_t* buf, size_t cap, size_t& len, uint32_t timeoutMs) override;
  void close() override;

 private:
  const char* name_;
  const char* host_;
  const char* path_;
  TlsStream tls_;
  uint8_t rxStore_[upstream::Forwarder::kMaxAnswer + 512];  // head + body
  upstream::HttpResponseParser parser_;
  uint8_t txBuf_[768];
};

// Plain DNS over UDP/53. NOT encrypted or authenticated: only used as a last resort.
class UdpTransport final : public upstream::ITransport {
 public:
  UdpTransport(const char* name, const char* ipv4, uint16_t port = 53);
  ~UdpTransport() override { close(); }

  const char* name() const override { return name_; }
  upstream::TransportKind kind() const override { return upstream::TransportKind::kUdp; }
  bool authenticated() const override { return false; }
  bool pipelined() const override { return true; }
  bool connected() const override { return fd_ >= 0; }
  upstream::IoStatus connect(uint32_t timeoutMs) override;
  upstream::IoStatus send(const uint8_t* msg, size_t len) override;
  upstream::IoStatus receive(uint8_t* buf, size_t cap, size_t& len, uint32_t timeoutMs) override;
  void close() override;

 private:
  const char* name_;
  char ip_[16];
  uint16_t port_;
  int fd_ = -1;
};

}  // namespace platform
